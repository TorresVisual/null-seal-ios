#![allow(clippy::unwrap_used)]

//! Encrypted backups kept on the relay's R2 bucket (#47): uploaded, listed, downloaded and
//! restored, and unreadable to the relay.

use core_crypto::KdfParams;
use core_store::Store;
use core_sync::backup::decode;
use core_sync::mock::MockRelay;
use core_sync::{Request, Response, SyncError, Transport, TransportError};
use seal_core::account::{
    Account, AccountError, BackupSecret, LoginFields, begin_setup, verify_backup,
};
use std::cell::RefCell;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn login(title: &str, password: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me".into(),
        password: password.into(),
        url: String::new(),
        notes: String::new(),
    }
}

fn params() -> KdfParams {
    KdfParams::new(19 * 1024, 2, 1).unwrap()
}

/// A registered account and its recovery code.
fn account_with_code(relay: &MockRelay) -> (Account, String) {
    let (mut s, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params()).unwrap();
    let mut a = s.confirm(&code, NOW).unwrap();
    a.register_with_relay(relay, "https://relay.example", "setup")
        .unwrap();
    (a, code.to_string())
}

fn account(relay: &MockRelay) -> Account {
    account_with_code(relay).0
}

#[test]
fn a_relay_backup_holds_no_master_wrapper_and_restores_with_the_recovery_code() {
    let relay = MockRelay::new(NOW);
    let (mut a, code) = account_with_code(&relay);
    a.save_login(None, &login("Bank", "bank-secret-pw"), NOW + 1)
        .unwrap();
    let key = a.backup_to_relay(&relay, NOW + 2).unwrap();

    let held = a.relay_backups(&relay, NOW + 3).unwrap();
    assert_eq!(held.len(), 1);
    assert_eq!(held[0].key, key);

    let file = a.download_relay_backup(&relay, NOW + 4, &key).unwrap();
    assert!(file.starts_with(b"NSBK")); // the sealed file, not the relay's text form

    // nothing in it to guess a master password against: the password does not open it
    assert!(matches!(
        verify_backup(&file, &BackupSecret::Password(PW), NOW + 5),
        Err(AccountError::NeedsRecoveryCode)
    ));
    let info = verify_backup(&file, &BackupSecret::Recovery(&code), NOW + 5).unwrap();
    assert_eq!(info.items, 1);

    let mut r = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Recovery(&code),
        NOW + 6,
    )
    .unwrap();
    // it has no master password yet
    assert!(matches!(
        r.unlock(PW, NOW + 7),
        Err(AccountError::NeedsRecoveryCode)
    ));
    // weak password and wrong code change nothing
    assert!(matches!(
        r.reset_master_password(&code, "short", params()),
        Err(AccountError::WeakPassword)
    ));
    assert!(
        r.reset_master_password("AAAAA-AAAAA", "another long passphrase 7!", params())
            .is_err()
    );
    let new_code = r
        .reset_master_password(&code, "another long passphrase 7!", params())
        .unwrap();
    assert_ne!(*new_code, code); // the recovery key rotates too
    r.unlock("another long passphrase 7!", NOW + 8).unwrap();
    let items = r.list_items().unwrap();
    assert_eq!(
        r.get_login(&items[0].id).unwrap().password,
        "bank-secret-pw"
    );

    // the local backup still works with the password: only the relay copy is stripped
    let local = a.backup(NOW + 9).unwrap();
    verify_backup(&local, &BackupSecret::Password(PW), NOW + 10).unwrap();

    // the relay saw only base64 of the sealed file: no title, no password
    let seen = relay.dump();
    assert!(!seen.contains("Bank") && !seen.contains("bank-secret-pw"));
}

#[test]
fn a_tampered_or_substituted_download_does_not_restore() {
    let relay = MockRelay::new(NOW);
    let (a, code) = account_with_code(&relay);
    let key = a.backup_to_relay(&relay, NOW + 1).unwrap();
    let mut file = a.download_relay_backup(&relay, NOW + 2, &key).unwrap();
    let last = file.len() - 1;
    file[last] ^= 1; // a relay that edits the stored object
    assert!(
        Account::restore(
            Store::open_in_memory().unwrap(),
            &file,
            &BackupSecret::Recovery(&code),
            NOW + 3
        )
        .is_err()
    );
}

#[test]
fn an_object_fetched_by_hand_from_the_bucket_decodes_to_the_same_file() {
    let relay = MockRelay::new(NOW);
    let a = account(&relay);
    let file = a.backup(NOW + 1).unwrap();
    // what the dashboard or `wrangler r2 object get` hands back: the stored base64 text
    let stored = format!("{}\n", core_sync_b64(&file));
    assert_eq!(decode(stored.as_bytes()).unwrap(), file);
    assert!(decode(b"not base64 !").is_none());
}

fn core_sync_b64(b: &[u8]) -> String {
    use base64::{Engine, engine::general_purpose::STANDARD};
    STANDARD.encode(b)
}

#[test]
fn only_the_newest_ten_are_kept() {
    let relay = MockRelay::new(NOW);
    let a = account(&relay);
    let keys: Vec<String> = (0..12)
        .map(|i| a.backup_to_relay(&relay, NOW + 100 + i).unwrap())
        .collect();
    let held: Vec<String> = a
        .relay_backups(&relay, NOW + 200)
        .unwrap()
        .into_iter()
        .map(|b| b.key)
        .collect();
    assert_eq!(held.len(), 10);
    assert_eq!(
        keys.iter().collect::<std::collections::HashSet<_>>().len(),
        12
    ); // all distinct
    assert_eq!(held[0], keys[11]); // newest first
    assert!(!held.contains(&keys[0]));
}

/// A relay whose owner did not enable R2 says so, and nothing else breaks.
#[test]
fn a_relay_without_r2_reports_backups_as_not_enabled() {
    let relay = MockRelay::new(NOW);
    relay.backups_enabled.set(false);
    let mut a = account(&relay);
    a.save_login(None, &login("Bank", "pw"), NOW + 1).unwrap();
    assert!(matches!(
        a.backup_to_relay(&relay, NOW + 2),
        Err(AccountError::Sync(SyncError::Status(501)))
    ));
    a.sync(&relay, NOW + 3).unwrap(); // sync is unaffected
}

/// Counts what leaves the client, to show a backup is one request.
struct Counting<'a>(&'a MockRelay, RefCell<usize>);
impl Transport for Counting<'_> {
    fn send(&self, r: &Request) -> Result<Response, TransportError> {
        *self.1.borrow_mut() += 1;
        self.0.send(r)
    }
}

#[test]
fn uploading_costs_one_request() {
    let relay = MockRelay::new(NOW);
    let a = account(&relay);
    let t = Counting(&relay, RefCell::new(0));
    a.backup_to_relay(&t, NOW + 1).unwrap();
    assert_eq!(*t.1.borrow(), 1);
}
