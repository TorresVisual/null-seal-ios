#![allow(clippy::unwrap_used)]

use super::*;
use core_sync::enroll::Joiner;
use core_sync::mock::MockRelay;
use core_sync::{Request, Response, TransportError};
use std::cell::Cell;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn params() -> KdfParams {
    KdfParams::new(19 * 1024, 2, 1).unwrap()
}

fn login(title: &str, password: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me@example.com".into(),
        password: password.into(),
        url: "https://example.com".into(),
        notes: String::new(),
    }
}

/// Enroll a new device through `by`, unlocked but not yet synced.
fn enroll(relay: &MockRelay, by: &Account, t: u64) -> Account {
    let (offer, code) = by.enroll_offer(relay, NOW + t).unwrap();
    let joiner = Joiner::new(&code).unwrap();
    joiner.send_request(relay).unwrap();
    let req = by.enroll_poll(&offer, relay, NOW + t).unwrap().unwrap();
    by.enroll_approve(&offer, &req, relay, NOW + t).unwrap();
    let payload = joiner.poll_result(relay).unwrap().unwrap();
    let mut d = Account::complete_join(
        Store::open_in_memory().unwrap(),
        &joiner,
        &payload,
        "https://relay.example",
    )
    .unwrap();
    d.unlock(PW, NOW + t).unwrap();
    d
}

struct Trio {
    relay: MockRelay,
    a: Account,
    b: Account,
    c: Account,
    /// A's recovery code from setup.
    code: String,
    ids: [String; 2],
}

/// Three enrolled, synced devices holding "Bank" and "Mail".
fn trio() -> Trio {
    let relay = MockRelay::new(NOW);
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params()).unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    a.register_with_relay(&relay, "https://relay.example", "setup")
        .unwrap();
    let bank = a
        .save_login(None, &login("Bank", "bank-pw-1"), NOW + 1)
        .unwrap();
    let mail = a
        .save_login(None, &login("Mail", "mail-pw-1"), NOW + 2)
        .unwrap();
    a.sync(&relay, NOW + 3).unwrap();
    let mut b = enroll(&relay, &a, 4);
    b.sync(&relay, NOW + 5).unwrap();
    let mut c = enroll(&relay, &a, 6);
    c.sync(&relay, NOW + 7).unwrap();
    a.sync(&relay, NOW + 8).unwrap();
    Trio {
        relay,
        a,
        b,
        c,
        code: code.to_string(),
        ids: [bank, mail],
    }
}

/// Revoke `ids` from `a` (a plain rotation if empty).
fn revoke(
    a: &mut Account,
    relay: &dyn Transport,
    ids: &[&str],
    t: u64,
) -> Result<(RevocationReport, String), AccountError> {
    let (rev, code) = a.begin_revocation(PW, ids.iter().map(|s| (*s).to_owned()).collect())?;
    let report = a.finish_revocation(rev, &code, relay, NOW + t)?;
    Ok((report, code.to_string()))
}

fn password_of(acct: &Account, id: &str) -> String {
    acct.get_login(id).unwrap().password
}

#[test]
fn the_device_list_shows_every_enrolled_device_as_verified() {
    let t = trio();
    let list = t.a.list_devices(&t.relay, NOW + 20).unwrap();
    assert_eq!(list.len(), 3);
    assert!(list.iter().all(|d| d.verified));
    // the relay saw A sign the list request itself; the other two have signed requests too
    assert!(list.iter().all(|d| d.last_seen.is_some()));
    assert_eq!(list.iter().filter(|d| d.current).count(), 1);
    assert!(list.iter().any(|d| d.id == t.c.device_id()));
}

#[test]
fn revoking_a_device_rotates_keys_so_it_cannot_read_new_data() {
    let mut t = trio();
    let c_id = t.c.device_id().to_owned();
    let [bank, _] = t.ids.clone();

    // a wrong password, a wrong retyped code and self-revocation are all refused up front
    assert!(t.a.begin_revocation("not the password", vec![]).is_err());
    assert!(matches!(
        t.a.begin_revocation(PW, vec![t.a.device_id().to_owned()]),
        Err(AccountError::RevokeSelf)
    ));
    let (rev, _) = t.a.begin_revocation(PW, vec![c_id.clone()]).unwrap();
    assert!(matches!(
        t.a.finish_revocation(rev, "wrong", &t.relay, NOW + 30),
        Err(AccountError::RecoveryMismatch)
    ));
    assert_eq!(t.a.list_devices(&t.relay, NOW + 31).unwrap().len(), 3);

    let (report, new_code) = revoke(&mut t.a, &t.relay, &[&c_id], 40).unwrap();
    assert_eq!((report.revoked, report.rekeyed), (1, 2));
    assert!(report.synced && report.reencrypted >= 2);
    assert!(t.a.recovery_code_opens(&new_code), "new recovery key works");
    assert!(
        !t.a.recovery_code_opens(&t.code),
        "old recovery key is retired"
    );

    // new data written after the revocation
    t.a.save_login(Some(&bank), &login("Bank", "bank-pw-2"), NOW + 50)
        .unwrap();
    t.a.sync(&t.relay, NOW + 51).unwrap();

    // the revoked device is locked out of the relay ...
    assert!(matches!(
        t.c.sync(&t.relay, NOW + 52),
        Err(AccountError::Sync(SyncError::Status(401)))
    ));
    // ... and even handed the raw record it cannot open it: its keys are the old generation
    let fresh = t.a.store.get(&bank).unwrap().unwrap();
    assert!(matches!(
        t.c.session.open_record(&fresh),
        Err(SessionError::UnknownKeyGen(1))
    ));
    assert_eq!(
        password_of(&t.c, &bank),
        "bank-pw-1",
        "only what it had before"
    );

    // the remaining device carries on with no re-enrollment, and can still unlock by password
    t.b.sync(&t.relay, NOW + 53).unwrap();
    assert_eq!(password_of(&t.b, &bank), "bank-pw-2");
    t.b.lock();
    t.b.unlock(PW, NOW + 54).unwrap();
    t.b.save_login(Some(&bank), &login("Bank", "bank-pw-3"), NOW + 55)
        .unwrap();
    t.b.sync(&t.relay, NOW + 56).unwrap();
    t.a.sync(&t.relay, NOW + 57).unwrap();
    assert_eq!(password_of(&t.a, &bank), "bank-pw-3");

    // every record of both devices is under the new generation, and the relay saw no secrets
    for acct in [&t.a, &t.b] {
        let current = acct
            .session
            .key_gen(&acct.meta.shared.vaults[0].id)
            .unwrap();
        assert_eq!(current, 1);
        for rec in acct.store.list(&acct.meta.shared.vaults[0].id).unwrap() {
            assert_eq!(blob_key_gen(&rec.blob).unwrap(), current);
        }
    }
    let seen = t.relay.dump();
    for secret in ["bank-pw-2", "bank-pw-3", PW, &new_code] {
        assert!(!seen.contains(secret), "relay saw {secret}");
    }
}

#[test]
fn a_plain_rotation_with_no_revocation_keeps_every_device_working() {
    let mut t = trio();
    let [bank, _] = t.ids.clone();
    // a device wrapper holds the retired Account Key, so a rotation must drop it (#76)
    let key = Key::random().unwrap();
    t.a.enable_device_unlock(&key).unwrap();
    t.b.enable_device_unlock(&key).unwrap();
    let (report, _) = revoke(&mut t.a, &t.relay, &[], 40).unwrap();
    assert_eq!((report.revoked, report.rekeyed), (0, 3));
    assert!(!t.a.device_unlock_enabled());
    for (i, acct) in [&mut t.b, &mut t.c].into_iter().enumerate() {
        acct.sync(&t.relay, NOW + 50 + i as u64).unwrap();
        assert_eq!(password_of(acct, &bank), "bank-pw-1");
    }
    assert!(!t.b.device_unlock_enabled());
}

#[test]
fn devices_that_have_not_proven_themselves_get_no_keys() {
    let mut t = trio();
    // a device enrolled but never synced has not published an attestation
    let fresh = enroll(&t.relay, &t.a, 20);
    let (rev, code) = t.a.begin_revocation(PW, vec![]).unwrap();
    let Err(AccountError::UnverifiedDevices(ids)) =
        t.a.finish_revocation(rev, &code, &t.relay, NOW + 21)
    else {
        panic!("rotation must refuse");
    };
    assert_eq!(ids, [fresh.device_id()]);

    // an attestation sealed under any key but the account's does not count either
    let rogue = Key::random().unwrap();
    let blob = seal(&rogue, 0, &attest_ctx(fresh.device_id()), b"{}").unwrap();
    devices::publish_attest(&t.relay, fresh.device.as_ref().unwrap(), NOW + 22, &blob).unwrap();
    let list = t.a.list_devices(&t.relay, NOW + 23).unwrap();
    assert!(
        list.iter()
            .any(|d| d.id == fresh.device_id() && !d.verified)
    );

    // revoking it alongside is fine
    let (report, _) = revoke(&mut t.a, &t.relay, &[fresh.device_id()], 24).unwrap();
    assert_eq!((report.revoked, report.rekeyed), (1, 3));
}

#[test]
fn records_under_a_key_we_lack_defer_instead_of_being_rejected() {
    let mut t = trio();
    revoke(&mut t.a, &t.relay, &[], 40).unwrap();
    // B has not synced since: pulling the re-sealed records before the new keys must not
    // consume them (the cursor would move past data B can then never read)
    let cursor_before = t.b.store.meta_get("sync.cursor").unwrap();
    assert!(matches!(
        t.b.pull_push(&t.relay, NOW + 41),
        Err(AccountError::Sync(SyncError::Deferred))
    ));
    assert_eq!(t.b.store.meta_get("sync.cursor").unwrap(), cursor_before);
    let report = t.b.sync(&t.relay, NOW + 42).unwrap();
    assert_eq!(report.rejected, 0);
    assert_eq!(password_of(&t.b, &t.ids[0]), "bank-pw-1");
}

#[test]
fn a_rekey_blob_that_does_not_open_changes_nothing() {
    let mut t = trio();
    let ids = [
        t.a.device_id().to_owned(),
        t.b.device_id().to_owned(),
        t.c.device_id().to_owned(),
    ];
    let junk: Vec<_> = ids
        .iter()
        .map(|id| (id.clone(), [&5u32.to_be_bytes()[..], &[7u8; 80]].concat()))
        .collect();
    let auth = Key::random().unwrap();
    devices::rotate(
        &t.relay,
        t.a.device.as_ref().unwrap(),
        NOW + 40,
        &[],
        &junk,
        &auth,
    )
    .unwrap();
    let before = t.b.meta.shared.ak_gen;
    t.b.sync(&t.relay, NOW + 41).unwrap();
    assert_eq!(t.b.meta.shared.ak_gen, before);
    assert_eq!(password_of(&t.b, &t.ids[0]), "bank-pw-1");

    // a stale one (older than what we hold) is dropped from the relay
    let stale: Vec<_> = ids
        .iter()
        .map(|id| (id.clone(), vec![0, 0, 0, 0, 1]))
        .collect();
    devices::rotate(
        &t.relay,
        t.a.device.as_ref().unwrap(),
        NOW + 42,
        &[],
        &stale,
        &auth,
    )
    .unwrap();
    t.b.sync(&t.relay, NOW + 43).unwrap();
    assert_eq!(
        devices::fetch_rekey(&t.relay, t.b.device.as_ref().unwrap(), NOW + 44).unwrap(),
        None
    );
}

/// Forwards to the relay until `budget` requests have been made; the request after that either
/// never arrives or (`lose_response`) arrives but its answer is lost; then everything fails.
struct Flaky<'a> {
    relay: &'a MockRelay,
    budget: Cell<usize>,
    lose_response: bool,
}

impl Transport for Flaky<'_> {
    fn send(&self, req: &Request) -> Result<Response, TransportError> {
        match self.budget.get() {
            0 => Err(TransportError("down".into())),
            n => {
                self.budget.set(n - 1);
                if n == 1 && self.lose_response {
                    let _ = self.relay.send(req);
                    return Err(TransportError("response lost".into()));
                }
                self.relay.send(req)
            }
        }
    }
}

fn requests(relay: &MockRelay) -> usize {
    relay.log.borrow().len()
}

/// Cut the network after every possible number of requests during a revocation (with the
/// answer to the cut request delivered or lost), then let everything sync normally: whichever
/// side of the commit point the cut fell on, every device ends up consistent.
#[test]
fn a_rotation_cut_off_at_any_request_still_converges() {
    // size the window with an uninterrupted run
    let probe = trio();
    let (mut a, relay) = (probe.a, probe.relay);
    let start = requests(&relay);
    let c_id = probe.c.device_id().to_owned();
    revoke(&mut a, &relay, &[&c_id], 40).unwrap();
    let window = requests(&relay) - start;
    assert!(window > 5);

    let (mut committed, mut aborted) = (0, 0);
    for lose_response in [false, true] {
        for budget in 0..=window {
            let mut t = trio();
            let [bank, mail] = t.ids.clone();
            // B has an unsynced edit made under the old keys; A edits too
            t.b.save_login(Some(&mail), &login("Mail", "mail-from-b"), NOW + 31)
                .unwrap();
            t.a.save_login(Some(&bank), &login("Bank", "bank-from-a"), NOW + 32)
                .unwrap();
            let c_id = t.c.device_id().to_owned();
            let flaky = Flaky {
                relay: &t.relay,
                budget: Cell::new(budget),
                lose_response,
            };
            let outcome = revoke(&mut t.a, &flaky, &[&c_id], 40);
            let at = format!(
                "budget {budget}, lose_response {lose_response}, outcome ok {}",
                outcome.is_ok()
            );

            // the network is back: everyone syncs a few rounds
            for i in 0..3 {
                t.a.sync_now(&t.relay, NOW + 100 + i * 10).unwrap();
                t.b.sync_now(&t.relay, NOW + 105 + i * 10).unwrap();
            }
            let rotated = t.c.sync(&t.relay, NOW + 200).is_err();
            let list = t.a.list_devices(&t.relay, NOW + 201).unwrap();
            assert_eq!(list.len(), if rotated { 2 } else { 3 }, "{at}");
            if outcome.is_ok() {
                assert!(rotated, "{at}");
            }
            if rotated {
                committed += 1;
            } else {
                aborted += 1;
            }
            if !rotated {
                // never committed: nothing was lost, C (and the others) keep working
                t.c.sync(&t.relay, NOW + 202).unwrap();
            }
            for acct in [&t.a, &t.b] {
                assert_eq!(password_of(acct, &bank), "bank-from-a", "{at}");
                assert_eq!(password_of(acct, &mail), "mail-from-b", "{at}");
                assert!(acct.store.pending().unwrap().is_empty(), "{at}");
            }
            if rotated {
                for acct in [&t.a, &t.b] {
                    let vault = &acct.meta.shared.vaults[0].id;
                    for rec in acct.store.list(vault).unwrap() {
                        assert_eq!(blob_key_gen(&rec.blob).unwrap(), 1, "{at}");
                    }
                }
            }
        }
    }
    assert!(
        committed > 0 && aborted > 0,
        "cuts must fall on both sides of the commit point"
    );
}

fn titles_of(a: &Account) -> Vec<String> {
    a.list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect()
}

/// A creates "Work" with one login in it and syncs; returns the vault id.
fn a_creates_work(t: &mut Trio) -> String {
    let work = t.a.create_vault("Work").unwrap();
    t.a.save_login(None, &login("vpn", "vpn-pw"), NOW + 50)
        .unwrap();
    t.a.sync(&t.relay, NOW + 51).unwrap();
    work
}

#[test]
fn a_vault_created_on_one_device_reaches_the_others_at_their_next_sync() {
    let mut t = trio();
    let work = a_creates_work(&mut t);

    for (i, acct) in [&mut t.b, &mut t.c].into_iter().enumerate() {
        assert_eq!(acct.list_vaults().unwrap().len(), 1);
        let report = acct.sync(&t.relay, NOW + 60 + i as u64).unwrap();
        assert_eq!(report.rejected, 0);
        let vaults = acct.list_vaults().unwrap();
        assert_eq!(vaults.len(), 2);
        assert_eq!(vaults[1].name, "Work");
        acct.select_vault(&work).unwrap();
        assert_eq!(titles_of(acct), ["vpn"]);
    }

    // the grant survives a lock and travels on: a device enrolled later gets it in its bundle
    t.b.lock();
    t.b.unlock(PW, NOW + 70).unwrap();
    assert_eq!(t.b.list_vaults().unwrap().len(), 2);
    let mut d = enroll(&t.relay, &t.b, 71);
    d.sync(&t.relay, NOW + 72).unwrap();
    d.select_vault(&work).unwrap();
    assert_eq!(titles_of(&d), ["vpn"]);
}

#[test]
fn a_device_that_pulled_before_the_grant_does_not_lose_the_records() {
    let mut t = trio();
    let work = a_creates_work(&mut t);

    // B pulls without having the vault: deferred, the cursor stays put (not rejected and skipped)
    let cursor = t.b.store.meta_get("sync.cursor").unwrap();
    assert!(matches!(
        t.b.pull_push(&t.relay, NOW + 60),
        Err(AccountError::Sync(SyncError::Deferred))
    ));
    assert_eq!(t.b.store.meta_get("sync.cursor").unwrap(), cursor);

    let report = t.b.sync(&t.relay, NOW + 61).unwrap();
    assert_eq!(report.rejected, 0);
    t.b.select_vault(&work).unwrap();
    assert_eq!(titles_of(&t.b), ["vpn"]);
}

#[test]
fn vault_grants_cannot_be_forged_by_the_relay_or_a_revoked_device() {
    let mut t = trio();
    let c_id = t.c.device_id().to_owned();
    let evil = |ak: &Key, ak_gen: u32, wrapped: String| {
        let device = t.c.device.as_ref().unwrap();
        let body = serde_json::to_vec(&Attest {
            pubkey: b64(&device.public_key()),
            x_pub: b64(&device.x_public().unwrap()),
            vaults: vec![VaultMeta {
                id: "evil".into(),
                key_gen: 0,
                wrapped_key: wrapped,
                old: Vec::new(),
                name: String::new(),
            }],
        })
        .unwrap();
        seal(ak, ak_gen, &attest_ctx(&c_id), &body).unwrap()
    };
    let publish = |blob: &[u8]| {
        devices::publish_attest(&t.relay, t.c.device.as_ref().unwrap(), NOW + 40, blob).unwrap();
    };

    // a relay without the Account Key: the grant is sealed under another key
    let rogue = Key::random().unwrap();
    let vk = new_vault_key().unwrap();
    let wrap = |k: &Key| b64(&wrap_vault_key(k, 0, b"evil", 0, &vk).unwrap());
    publish(&evil(&rogue, 0, wrap(&rogue)));
    t.a.sync(&t.relay, NOW + 41).unwrap();
    // an attestation under the right key whose wrapped key is not the account's
    let ak = Key::from_bytes(*t.a.session.account_key().unwrap().expose());
    publish(&evil(&ak, 0, wrap(&rogue)));
    t.a.sync(&t.relay, NOW + 42).unwrap();
    assert_eq!(t.a.list_vaults().unwrap().len(), 1);

    // a revoked device is cut off from the relay, and what it creates never arrives
    revoke(&mut t.a, &t.relay, &[&c_id], 50).unwrap();
    t.c.create_vault("Sneaky").unwrap();
    assert!(t.c.sync(&t.relay, NOW + 51).is_err());
    t.a.sync(&t.relay, NOW + 52).unwrap();
    t.b.sync(&t.relay, NOW + 53).unwrap();
    assert_eq!(t.a.list_vaults().unwrap().len(), 1);
    assert_eq!(t.b.list_vaults().unwrap().len(), 1);
}
