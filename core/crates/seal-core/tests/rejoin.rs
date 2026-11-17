#![allow(clippy::unwrap_used)]

//! A device restored from a backup rejoins the relay that still holds its account (#124),
//! through a surviving device or, when none is left, by proving it holds the Account Key.

use core_crypto::KdfParams;
use core_store::Store;
use core_sync::SyncError;
use core_sync::enroll::Joiner;
use core_sync::mock::MockRelay;
use seal_core::account::{Account, AccountError, BackupSecret, LoginFields, begin_setup};

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";
const URL: &str = "https://relay.example";

fn login(title: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me".into(),
        password: "pw".into(),
        url: String::new(),
        notes: String::new(),
    }
}

/// A new account registered on `relay`, unlocked and synced.
fn account(relay: &MockRelay) -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut s, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = s.confirm(&code, NOW).unwrap();
    a.register_with_relay(relay, URL, "setup").unwrap();
    a.sync(relay, NOW + 1).unwrap();
    a
}

/// Enroll a second device through `by` and let it sync once so the account vouches for it.
fn enroll(relay: &MockRelay, by: &Account, t: u64) -> Account {
    let (offer, code) = by.enroll_offer(relay, NOW + t).unwrap();
    let joiner = Joiner::new(&code).unwrap();
    joiner.send_request(relay).unwrap();
    let req = by.enroll_poll(&offer, relay, NOW + t).unwrap().unwrap();
    by.enroll_approve(&offer, &req, relay, NOW + t).unwrap();
    let payload = joiner.poll_result(relay).unwrap().unwrap();
    let mut d =
        Account::complete_join(Store::open_in_memory().unwrap(), &joiner, &payload, URL).unwrap();
    d.unlock(PW, NOW + t).unwrap();
    d.sync(relay, NOW + t + 1).unwrap();
    d
}

fn restore(file: &[u8], t: u64) -> Account {
    let mut r = Account::restore(
        Store::open_in_memory().unwrap(),
        file,
        &BackupSecret::Password(PW),
        NOW + t,
    )
    .unwrap();
    r.unlock(PW, NOW + t + 1).unwrap();
    r
}

fn titles(a: &Account) -> Vec<String> {
    let mut t: Vec<String> = a
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    t.sort();
    t
}

/// Run the surviving-device enrollment for a restored `r`, returning the reply.
fn rejoin_via(relay: &MockRelay, by: &Account, r: &Account, t: u64) -> Vec<u8> {
    let (offer, code) = by.enroll_offer(relay, NOW + t).unwrap();
    let joiner = r.rejoin_joiner(&code).unwrap();
    joiner.send_request(relay).unwrap();
    let req = by.enroll_poll(&offer, relay, NOW + t).unwrap().unwrap();
    assert_eq!(
        req.device_id,
        r.device_id(),
        "the restored identity is kept"
    );
    by.enroll_approve(&offer, &req, relay, NOW + t).unwrap();
    joiner.poll_result(relay).unwrap().unwrap().to_vec()
}

fn refused(e: AccountError) -> bool {
    matches!(e, AccountError::Sync(SyncError::Status(401)))
}

#[test]
fn with_no_surviving_device_the_account_key_is_the_proof() {
    let relay = MockRelay::new(NOW);
    let mut a = account(&relay);
    a.save_login(None, &login("Bank"), NOW + 2).unwrap();
    let file = a.backup(NOW + 3).unwrap();
    a.save_login(None, &login("Mail"), NOW + 4).unwrap(); // after the backup, only on the relay
    a.sync(&relay, NOW + 5).unwrap();
    drop(a); // every enrolled device is gone

    let mut r = restore(&file, 10);
    assert!(matches!(
        r.sync(&relay, NOW + 12),
        Err(AccountError::NoRelay)
    ));
    r.rejoin_relay(&relay, URL, NOW + 13).unwrap();
    assert_eq!(r.relay_url(), Some(URL));
    r.save_login(None, &login("Extra"), NOW + 14).unwrap();
    r.sync(&relay, NOW + 15).unwrap();
    assert_eq!(titles(&r), ["Bank", "Extra", "Mail"]);
    assert_eq!(relay.record_count(), 3);

    // it is an ordinary device now: a later restore reaches the same state
    let file = r.backup(NOW + 16).unwrap();
    let mut r2 = restore(&file, 20);
    r2.rejoin_relay(&relay, URL, NOW + 23).unwrap();
    r2.sync(&relay, NOW + 24).unwrap();
    assert_eq!(titles(&r2), ["Bank", "Extra", "Mail"]);
}

#[test]
fn through_a_surviving_device_the_restored_identity_is_kept() {
    let relay = MockRelay::new(NOW);
    let mut a = account(&relay);
    a.save_login(None, &login("Bank"), NOW + 2).unwrap();
    a.sync(&relay, NOW + 3).unwrap();
    let file = a.backup(NOW + 4).unwrap();
    a.save_login(None, &login("Mail"), NOW + 5).unwrap();
    a.sync(&relay, NOW + 6).unwrap();

    let mut r = restore(&file, 10);
    let payload = rejoin_via(&relay, &a, &r, 12);
    r.finish_rejoin(&payload, URL).unwrap();

    r.save_login(None, &login("Extra"), NOW + 13).unwrap();
    r.sync(&relay, NOW + 14).unwrap();
    a.sync(&relay, NOW + 15).unwrap();
    assert_eq!(titles(&r), ["Bank", "Extra", "Mail"]);
    assert_eq!(titles(&a), titles(&r));
}

#[test]
fn a_relay_that_is_not_the_accounts_never_takes_the_device() {
    let relay = MockRelay::new(NOW);
    let a = account(&relay);
    let file = a.backup(NOW + 2).unwrap();
    let mut r = restore(&file, 10);

    // a relay that was never this account's, and one that holds a different account
    let empty = MockRelay::new(NOW);
    let other = MockRelay::new(NOW);
    let _someone_else = account(&other);
    for foreign in [&empty, &other] {
        assert!(refused(r.rejoin_relay(foreign, URL, NOW + 12).unwrap_err()));
        assert_eq!(r.relay_url(), None);
    }
    r.rejoin_relay(&relay, URL, NOW + 13).unwrap(); // the real one still works
}

#[test]
fn a_backup_from_before_a_revocation_cannot_get_back_in() {
    let relay = MockRelay::new(NOW);
    let mut a = account(&relay);
    let b = enroll(&relay, &a, 5);
    a.sync(&relay, NOW + 8).unwrap();
    let file = a.backup(NOW + 9).unwrap(); // holds the Account Key that is about to be retired

    let (rev, code) = a
        .begin_revocation(PW, vec![b.device_id().to_owned()])
        .unwrap();
    a.finish_revocation(rev, &code, &relay, NOW + 10).unwrap();

    let mut stale = restore(&file, 20);
    assert!(refused(
        stale.rejoin_relay(&relay, URL, NOW + 22).unwrap_err()
    ));
    let payload = rejoin_via(&relay, &a, &stale, 23);
    assert!(matches!(
        stale.finish_rejoin(&payload, URL),
        Err(AccountError::StaleBackup)
    ));
    assert_eq!(stale.relay_url(), None);

    // a backup taken after the rotation is fine
    let file = a.backup(NOW + 30).unwrap();
    restore(&file, 40)
        .rejoin_relay(&relay, URL, NOW + 42)
        .unwrap();
}

#[test]
fn a_rebuilt_relay_takes_the_restored_device_with_the_setup_token() {
    let old = MockRelay::new(NOW);
    let mut a = account(&old);
    a.save_login(None, &login("Bank"), NOW + 2).unwrap();
    let file = a.backup(NOW + 3).unwrap();

    let new = MockRelay::new(NOW);
    let mut r = restore(&file, 10);
    r.register_with_relay(&new, URL, "setup").unwrap();
    r.sync(&new, NOW + 12).unwrap();
    assert_eq!(new.record_count(), 1);

    // the rebuilt relay now knows the account, so a second restore can rejoin with no device left
    drop(r);
    let mut r2 = restore(&file, 20);
    r2.rejoin_relay(&new, URL, NOW + 22).unwrap();
    r2.sync(&new, NOW + 23).unwrap();
    assert_eq!(titles(&r2), ["Bank"]);
}

#[test]
fn a_live_device_moved_to_a_rebuilt_relay_publishes_the_key_again() {
    let old = MockRelay::new(NOW);
    let mut a = account(&old);
    a.save_login(None, &login("Bank"), NOW + 2).unwrap();
    a.sync(&old, NOW + 3).unwrap(); // already published the account key to the old relay

    let new = MockRelay::new(NOW);
    a.register_with_relay(&new, URL, "setup").unwrap();
    a.sync(&new, NOW + 5).unwrap();
    assert_eq!(new.record_count(), 1);

    let file = a.backup(NOW + 6).unwrap();
    drop(a);
    let mut r = restore(&file, 10);
    r.rejoin_relay(&new, URL, NOW + 12).unwrap(); // the rebuilt relay learned the key
    r.sync(&new, NOW + 13).unwrap();
    assert_eq!(titles(&r), ["Bank"]);
}
