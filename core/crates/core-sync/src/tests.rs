#![allow(clippy::unwrap_used)]

use crate::enroll::{Joiner, Offer, new_code};
use crate::mock::MockRelay;
use crate::{Clock, Device, SyncError, register_first_device, sync};
use core_crypto::Key;
use core_store::{Record, Store};

const NOW: u64 = 1_800_000_000_000;
const VAULT: &str = "vault-1";

struct Client {
    store: Store,
    clock: Clock,
    device: Device,
}

impl Client {
    fn new(id: &str, node: u32) -> Self {
        let store = Store::open_in_memory().unwrap();
        let clock = Clock::load(&store, node).unwrap();
        let device = Device {
            id: id.into(),
            seed: Key::random().unwrap(),
        };
        Self {
            store,
            clock,
            device,
        }
    }

    /// Local create/edit/delete of an opaque record (sync never looks inside blobs).
    fn write(&mut self, id: &str, blob: &[u8], tomb: bool, now: u64) -> String {
        let hlc = self.clock.tick(&self.store, now).unwrap();
        let rec = Record {
            id: id.into(),
            vault: VAULT.into(),
            hlc: hlc.clone(),
            tombstone: tomb,
            blob: blob.to_vec(),
        };
        assert!(self.store.put_local(&rec).unwrap());
        hlc
    }

    fn sync(&mut self, relay: &MockRelay) -> Result<crate::SyncReport, SyncError> {
        sync(
            &self.store,
            &mut self.clock,
            relay,
            &self.device,
            NOW,
            &|_| crate::Verdict::Accept,
            &crate::lww,
        )
    }

    fn get(&self, id: &str) -> Option<Record> {
        self.store.get(id).unwrap()
    }
}

/// Relay with client `a` registered as the first device.
fn setup() -> (MockRelay, Client) {
    let relay = MockRelay::new(NOW);
    let a = Client::new("dev-a", 1);
    register_first_device(&relay, &a.device, "setup").unwrap();
    (relay, a)
}

#[test]
fn edit_create_and_delete_propagate_between_clients() {
    let (relay, mut a) = setup();
    let mut b = Client::new("dev-b", 2);
    // b joins the relay through the first-device path only for the test; enrollment has its own tests
    let code = new_code().unwrap();
    let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
    let joiner = Joiner::new(&code).unwrap();
    joiner.send_request(&relay).unwrap();
    let req = offer.poll(&relay, &a.device, NOW).unwrap().unwrap();
    offer.approve(&relay, &a.device, NOW, &req, b"x").unwrap();
    joiner.poll_result(&relay).unwrap().unwrap();
    b.device = joiner.device();

    a.write("r1", b"v1", false, NOW);
    let rep = a.sync(&relay).unwrap();
    assert_eq!(rep.pushed, 1);
    b.sync(&relay).unwrap();
    assert_eq!(b.get("r1").unwrap().blob, b"v1");

    a.write("r1", b"v2", false, NOW + 10);
    a.sync(&relay).unwrap();
    b.sync(&relay).unwrap();
    assert_eq!(b.get("r1").unwrap().blob, b"v2");

    b.write("r1", b"gone", true, NOW + 20);
    b.sync(&relay).unwrap();
    a.sync(&relay).unwrap();
    assert!(a.get("r1").unwrap().tombstone);
    assert!(a.store.pending().unwrap().is_empty() && b.store.pending().unwrap().is_empty());

    // nothing left to do: a second sync is a no-op
    let again = a.sync(&relay).unwrap();
    assert_eq!((again.pushed, again.applied, again.conflicts), (0, 0, 0));
}

#[test]
fn concurrent_edits_converge_on_the_later_hlc() {
    let (relay, mut a) = setup();
    let mut b = Client::new("dev-b", 2);
    b.device = {
        // reuse a's identity on the relay under a second store to keep the test short
        Device {
            id: a.device.id.clone(),
            seed: Key::from_bytes(*a.device.seed.expose()),
        }
    };
    a.write("r1", b"base", false, NOW);
    a.sync(&relay).unwrap();
    b.sync(&relay).unwrap();

    a.write("r1", b"from-a", false, NOW + 100);
    b.write("r1", b"from-b", false, NOW + 200); // later wall time: wins
    a.sync(&relay).unwrap();
    let rep = b.sync(&relay).unwrap();
    assert!(rep.conflicts >= 1 || rep.applied == 0);
    a.sync(&relay).unwrap();
    assert_eq!(a.get("r1").unwrap().blob, b"from-b");
    assert_eq!(b.get("r1").unwrap().blob, b"from-b");
    assert!(a.store.pending().unwrap().is_empty() && b.store.pending().unwrap().is_empty());
}

#[test]
fn skewed_clock_cannot_undercut_an_observed_edit() {
    let (relay, mut a) = setup();
    let mut b = Client::new("dev-b", 2);
    b.device = Device {
        id: a.device.id.clone(),
        seed: Key::from_bytes(*a.device.seed.expose()),
    };
    let first = a.write("r1", b"a", false, NOW + 60_000); // a's clock runs a minute fast
    a.sync(&relay).unwrap();
    b.sync(&relay).unwrap();
    let second = b.write("r1", b"b", false, NOW); // b's wall clock is behind
    assert!(second > first, "{second} must beat {first}");
    b.sync(&relay).unwrap();
    a.sync(&relay).unwrap();
    assert_eq!(a.get("r1").unwrap().blob, b"b");
}

#[test]
fn pulls_more_than_one_page_and_pushes_in_batches() {
    let (relay, mut a) = setup();
    for i in 0..230 {
        a.write(&format!("r{i}"), &[i as u8], false, NOW);
    }
    let rep = a.sync(&relay).unwrap();
    assert_eq!(rep.pushed, 230);
    assert_eq!(relay.record_count(), 230);
    let mut b = Client::new("dev-b", 2);
    b.device = Device {
        id: a.device.id.clone(),
        seed: Key::from_bytes(*a.device.seed.expose()),
    };
    let rep = b.sync(&relay).unwrap();
    assert_eq!(rep.applied, 230);
    assert_eq!(b.store.list(VAULT).unwrap().len(), 230);
}

#[test]
fn unregistered_or_mistimed_devices_are_refused() {
    let (relay, _a) = setup();
    let mut stranger = Client::new("dev-x", 3);
    stranger.write("r", b"x", false, NOW);
    assert!(matches!(stranger.sync(&relay), Err(SyncError::Status(401))));
    assert_eq!(relay.record_count(), 0);

    let (relay, mut a) = setup();
    relay.now_ms.set(NOW + 10 * 60_000); // device clock off by 10 minutes
    assert!(matches!(a.sync(&relay), Err(SyncError::Status(401))));
}

#[test]
fn rejects_malformed_relay_records_without_crashing() {
    let (relay, mut a) = setup();
    // a record with a stamp far in the future (hostile or broken device) is not applied
    let evil = Record {
        id: "evil".into(),
        vault: VAULT.into(),
        hlc: "ffffffffffff000000000001".into(),
        tombstone: false,
        blob: vec![1],
    };
    a.store.put_local(&evil).unwrap();
    a.sync(&relay).unwrap(); // pushed as-is: the relay does not judge stamps
    let mut b = Client::new("dev-b", 2);
    b.device = Device {
        id: a.device.id.clone(),
        seed: Key::from_bytes(*a.device.seed.expose()),
    };
    let rep = b.sync(&relay).unwrap();
    assert_eq!(rep.rejected, 1);
    assert!(b.get("evil").is_none());
    assert!(
        b.clock
            .tick(&b.store, NOW)
            .unwrap()
            .starts_with(&format!("{NOW:012x}"))
    );
}

mod enrollment {
    use super::*;

    fn pair() -> (MockRelay, Client, String) {
        let (relay, a) = setup();
        (relay, a, new_code().unwrap().to_string())
    }

    #[test]
    fn delivers_the_payload_and_registers_the_device() {
        let (relay, a, code) = pair();
        let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
        let joiner = Joiner::new(&code).unwrap();
        assert!(offer.poll(&relay, &a.device, NOW).unwrap().is_none());
        assert!(joiner.poll_result(&relay).unwrap().is_none());
        joiner.send_request(&relay).unwrap();
        let req = offer.poll(&relay, &a.device, NOW).unwrap().unwrap();
        assert_eq!(req.device_id, joiner.device().id);

        let secret = b"account-key-0123456789abcdef-0123";
        offer.approve(&relay, &a.device, NOW, &req, secret).unwrap();
        let got = joiner.poll_result(&relay).unwrap().unwrap();
        assert_eq!(&got[..], secret);

        // the new device can now talk to the relay
        let mut b = Client::new("unused", 2);
        b.device = joiner.device();
        b.sync(&relay).unwrap();

        // the relay saw neither the code nor the payload in any form
        let seen = relay.dump();
        assert!(!seen.contains(&code.replace('-', "")) && !seen.contains(&code));
        assert!(!seen.contains("account-key"));
        let b64 = |b: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b);
        assert!(!seen.contains(&b64(secret)));
    }

    #[test]
    fn code_is_single_use_and_replays_fail() {
        let (relay, a, code) = pair();
        let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
        let joiner = Joiner::new(&code).unwrap();
        joiner.send_request(&relay).unwrap();
        // a second device with the same code cannot post another request
        let intruder = Joiner::new(&code).unwrap();
        assert!(matches!(
            intruder.send_request(&relay),
            Err(SyncError::Status(409))
        ));
        let req = offer.poll(&relay, &a.device, NOW).unwrap().unwrap();
        offer.approve(&relay, &a.device, NOW, &req, b"p").unwrap();
        assert!(joiner.poll_result(&relay).unwrap().is_some());
        // the result is one shot, the session is gone, approving again fails
        assert!(joiner.poll_result(&relay).unwrap().is_none());
        assert!(matches!(
            offer.approve(&relay, &a.device, NOW, &req, b"p"),
            Err(SyncError::Status(409))
        ));
        assert!(matches!(
            joiner.send_request(&relay),
            Err(SyncError::Status(409))
        ));
        assert!(
            Offer::start(&relay, &a.device, &code, NOW).is_ok(),
            "a new session may reuse the id after the old one is consumed"
        );
    }

    #[test]
    fn code_expires() {
        let (relay, a, code) = pair();
        let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
        let joiner = Joiner::new(&code).unwrap();
        relay.now_ms.set(NOW + 11 * 60_000);
        let late = Device {
            id: a.device.id.clone(),
            seed: Key::from_bytes(*a.device.seed.expose()),
        };
        assert!(matches!(
            joiner.send_request(&relay),
            Err(SyncError::Status(409))
        ));
        assert!(matches!(
            offer.poll(&relay, &late, NOW + 11 * 60_000),
            Err(SyncError::Status(404))
        ));
    }

    #[test]
    fn a_relay_or_attacker_without_the_code_cannot_obtain_the_key() {
        let (relay, a, code) = pair();
        let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
        // attacker knows the session id from the relay but not the code: it can only guess a MAC
        let wrong = Joiner::new(&new_code().unwrap()).unwrap();
        let forged = serde_json::json!({
            "device_id": "attacker", "pubkey": crate::b64(&wrong.device().public_key()),
            "x_pub": crate::b64(&wrong.device().public_key()), "mac": crate::b64(&[0u8; 32]),
        });
        let sid = {
            let r = relay
                .log
                .borrow()
                .iter()
                .find(|l| l.starts_with("POST /v1/enroll "))
                .cloned()
                .unwrap();
            let v: serde_json::Value = serde_json::from_str(&r[r.rfind('{').unwrap()..]).unwrap();
            v["sid"].as_str().unwrap().to_owned()
        };
        let put = crate::Request {
            method: "PUT",
            path: format!("/v1/enroll/{sid}/request"),
            headers: vec![],
            body: forged.to_string().into_bytes(),
        };
        assert_eq!(crate::Transport::send(&relay, &put).unwrap().status, 204);
        // the existing device refuses to approve a request with a bad MAC
        assert!(matches!(
            offer.poll(&relay, &a.device, NOW),
            Err(SyncError::Crypto)
        ));
        assert_eq!(relay.record_count(), 0);
    }

    #[test]
    fn wrong_or_malformed_codes_are_rejected() {
        let (relay, a, code) = pair();
        assert!(Joiner::new("1234").is_err());
        assert!(
            Offer::start(
                &relay,
                &a.device,
                "zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz-zzzz",
                NOW
            )
            .is_err()
        );
        // right shape, wrong secret: the new device's MAC does not verify for the offer
        let offer = Offer::start(&relay, &a.device, &code, NOW).unwrap();
        let other = Joiner::new(&new_code().unwrap()).unwrap();
        assert!(matches!(
            other.send_request(&relay),
            Err(SyncError::Status(409))
        )); // unknown session
        assert!(offer.poll(&relay, &a.device, NOW).unwrap().is_none());
        // codes tolerate case, spaces and missing dashes
        let loose = code.replace('-', " ").to_uppercase();
        assert!(Joiner::new(&loose).is_ok());
    }
}

/// Pins the account-auth derivation (#124): changing it would lock every existing backup out of
/// the relay's recovery path, so it must be a deliberate, versioned change.
#[test]
fn account_auth_key_is_pinned() {
    let auth = crate::devices::account_auth(&Key::from_bytes([7; 32])).unwrap();
    assert_eq!(
        crate::b64(&core_crypto::signing_public(&auth)),
        "/ZUPayxinknb24RL7ltjDzlUaGC+GCK5Q9COa3Avh0E="
    );
}
