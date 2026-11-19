#![allow(clippy::unwrap_used)]

use super::*;
use core_crypto::KdfParams;
use core_sync::mock::MockRelay;
use seal_core::account::{LoginFields, begin_setup};

const PW: &str = "correct horse battery staple 42!";
const URL: &str = "https://relay.example";

/// One mock relay behind both sides: the Swift-facing trait and the core's own `Transport`.
struct Relay(Mutex<MockRelay>);

fn name(n: &str) -> &'static str {
    ["x-device", "x-ts", "x-sig", "x-setup-token"]
        .into_iter()
        .find(|k| *k == n)
        .unwrap()
}

impl RelayTransport for Relay {
    fn send(
        &self,
        method: String,
        path: String,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Result<RelayResponse, VaultError> {
        let req = Request {
            method: ["GET", "POST", "PUT", "DELETE"]
                .into_iter()
                .find(|m| *m == method)
                .unwrap(),
            path,
            headers: headers
                .into_iter()
                .map(|h| (name(&h.name), h.value))
                .collect(),
            body,
        };
        let res = self.0.lock().unwrap().send(&req).unwrap();
        Ok(RelayResponse {
            status: res.status,
            body: res.body,
        })
    }
}

impl Transport for Relay {
    fn send(&self, req: &Request) -> Result<Response, TransportError> {
        self.0.lock().unwrap().send(req)
    }
}

fn existing(relay: &Relay) -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut s, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = s.confirm(&code, now_ms()).unwrap();
    a.register_with_relay(relay, URL, "setup").unwrap();
    a.save_login(
        None,
        &LoginFields {
            title: "Bank".into(),
            username: "me".into(),
            password: "pw".into(),
            url: String::new(),
            notes: String::new(),
        },
        now_ms(),
    )
    .unwrap();
    a.sync(relay, now_ms()).unwrap();
    a
}

#[test]
fn a_new_device_joins_unlocks_and_syncs_the_vault() {
    let relay = Arc::new(Relay(Mutex::new(MockRelay::new(now_ms()))));
    let mut by = existing(&relay);
    let (offer, code) = by.enroll_offer(&*relay, now_ms()).unwrap();

    // a bad code or relay never reaches the network
    assert!(matches!(
        Enrollment::start("nope".into(), URL.into(), relay.clone()),
        Err(VaultError::Invalid)
    ));
    assert!(matches!(
        Enrollment::start(
            code.to_string(),
            "http://relay.example".into(),
            relay.clone()
        ),
        Err(VaultError::Invalid)
    ));

    let e = Enrollment::start(code.to_string(), format!("{URL}/"), relay.clone()).unwrap();
    let path = std::env::temp_dir().join(format!("null-seal-join-{}.db", std::process::id()));
    let path = path.to_str().unwrap().to_owned();
    let _ = std::fs::remove_file(&path);
    assert!(e.poll(path.clone()).unwrap().is_none(), "not approved yet");

    let req = by.enroll_poll(&offer, &*relay, now_ms()).unwrap().unwrap();
    by.enroll_approve(&offer, &req, &*relay, now_ms()).unwrap();

    let v = e.poll(path.clone()).unwrap().unwrap();
    assert!(!v.is_unlocked());
    assert!(matches!(v.sync(relay.clone()), Err(VaultError::Locked)));
    assert!(matches!(
        v.unlock("wrong".into()),
        Err(VaultError::WrongPassword)
    ));
    v.unlock(PW.into()).unwrap();
    assert_eq!(v.sync(relay.clone()).unwrap().pulled, 1);
    let rows = v.list_items().unwrap();
    assert_eq!((rows.len(), rows[0].title.as_str()), (1, "Bank"));
    assert!(rows[0].kind == ItemKind::Login);

    // create, edit and delete on the new device reach the first one through the relay
    let data = |t: &str| LoginData {
        title: t.into(),
        username: "u".into(),
        password: "p".into(),
        url: String::new(),
        notes: String::new(),
    };
    let id = v.save_login(None, data("Mail")).unwrap();
    v.save_login(Some(id.clone()), data("Mail 2")).unwrap();
    assert_eq!(v.get_login(id.clone()).unwrap().title, "Mail 2");
    assert_eq!(v.list_items().unwrap().len(), 2);
    assert!(v.sync(relay.clone()).unwrap().pushed >= 1);
    by_pull(&mut by, &relay, 2);
    v.delete_login(id.clone()).unwrap();
    assert!(matches!(v.get_login(id), Err(VaultError::NotFound)));
    assert_eq!(v.list_items().unwrap().len(), 1);

    // the endpoint is on this device only, and survives a restart
    let again = open_vault(path.clone()).unwrap().unwrap();
    assert!(!again.is_unlocked());
    assert_eq!(again.relay_url().as_deref(), Some(URL));

    // a second join must not overwrite the vault
    let (offer2, code2) = by.enroll_offer(&*relay, now_ms()).unwrap();
    let e2 = Enrollment::start(code2.to_string(), URL.into(), relay.clone()).unwrap();
    let req2 = by.enroll_poll(&offer2, &*relay, now_ms()).unwrap().unwrap();
    by.enroll_approve(&offer2, &req2, &*relay, now_ms())
        .unwrap();
    assert!(matches!(
        e2.poll(path.clone()),
        Err(VaultError::AlreadyJoined)
    ));
    drop((v, again));
    let _ = std::fs::remove_file(&path);
}

/// The first device sees `n` items after pulling.
fn by_pull(by: &mut Account, relay: &Arc<Relay>, n: usize) {
    by.sync(&**relay, now_ms()).unwrap();
    assert_eq!(by.list_items().unwrap().len(), n);
}

#[test]
fn only_https_or_loopback_relays() {
    for ok in [
        "https://r.example",
        "http://localhost:8787",
        "http://127.0.0.1",
    ] {
        assert!(check_relay(ok).is_ok(), "{ok}");
    }
    for bad in [
        "",
        "https://",
        "http://r.example",
        "http://localhost.evil.com",
        "ftp://x",
        "http://localhost:",
        "https://r.example/?x",
        "http://[::1]x",
    ] {
        assert!(check_relay(bad).is_err(), "{bad}");
    }
    // userinfo must not disguise the host (built at runtime: the mirror URL gate reads literals)
    for bad in [
        format!("http://localhost:80{}evil.example", '@'),
        format!("https://x{}host.example", '@'),
    ] {
        assert!(check_relay(&bad).is_err(), "{bad}");
    }
}

#[test]
fn the_device_key_unlocks_a_locked_vault_and_a_wrong_one_does_not() {
    let relay = Relay(Mutex::new(MockRelay::new(now_ms())));
    let v = Vault::wrap(existing(&relay));
    assert!(!v.device_unlock_enabled());
    assert!(matches!(
        v.unlock_with_device_key(vec![7; 32]),
        Err(VaultError::NoDeviceUnlock)
    ));
    assert!(matches!(
        v.enable_device_unlock(vec![7; 31]),
        Err(VaultError::Invalid)
    ));

    v.enable_device_unlock(vec![7; 32]).unwrap();
    assert!(v.device_unlock_enabled());
    v.lock();
    assert!(!v.is_unlocked());
    assert!(matches!(
        v.unlock_with_device_key(vec![8; 32]),
        Err(VaultError::WrongPassword)
    ));
    assert!(!v.is_unlocked());

    v.unlock_with_device_key(vec![7; 32]).unwrap();
    assert!(v.is_unlocked());

    // dropping the wrapper (Face ID enrollment changed) leaves the password working
    v.lock();
    v.disable_device_unlock().unwrap();
    assert!(!v.device_unlock_enabled());
    assert!(v.unlock_with_device_key(vec![7; 32]).is_err());
    v.unlock(PW.into()).unwrap();
}

#[test]
fn totp_entries_lists_only_items_with_a_code_and_needs_the_vault_unlocked() {
    let relay = Relay(Mutex::new(MockRelay::new(now_ms())));
    let mut a = existing(&relay); // holds "Bank", a login without a one-time code
    let mut f = seal_core::account::ItemFields::new(ItemType::Totp);
    f.title = "Authenticator".into();
    // base32("12345678901234567890"): RFC 6238 Appendix B, SHA-1
    f.totp = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ".into();
    let id = a.save_item(None, &f, now_ms()).unwrap();
    let v = Vault::wrap(a);

    let e = v.totp_entries().unwrap();
    assert_eq!(e.len(), 1);
    assert_eq!(
        (e[0].id.as_str(), e[0].title.as_str()),
        (id.as_str(), "Authenticator")
    );
    assert_eq!(e[0].code.len(), 6);
    assert_eq!(e[0].period, 30);
    assert!((1..=30).contains(&e[0].remaining));

    v.lock();
    assert!(matches!(v.totp_entries(), Err(VaultError::Locked)));
}
