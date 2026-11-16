#![allow(clippy::unwrap_used)]

use super::*;

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
        notes: "note".into(),
    }
}

/// An unlocked account with two live items and one deleted, plus its recovery code.
fn account() -> (Account, String) {
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params()).unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    a.save_login(None, &login("Bank", "bank-pw"), NOW + 1)
        .unwrap();
    a.save_login(None, &login("Mail", "mail-pw"), NOW + 2)
        .unwrap();
    let gone = a
        .save_login(None, &login("Gone", "gone-pw"), NOW + 3)
        .unwrap();
    a.delete_login(&gone, NOW + 4).unwrap();
    (a, code.to_string())
}

fn all_records(a: &Account) -> Vec<Record> {
    a.store.list(&a.meta.shared.vaults[0].id).unwrap()
}

#[test]
fn restore_on_a_clean_profile_yields_the_identical_vault() {
    let (a, _) = account();
    let file = a.backup(NOW + 10).unwrap();

    let mut b = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Password(PW),
        NOW + 20,
    )
    .unwrap();
    assert_eq!(b.state(), State::Locked);
    assert_ne!(b.device_id(), a.device_id(), "a restore is a new device");
    b.unlock(PW, NOW + 21).unwrap();

    assert_eq!(all_records(&a), all_records(&b)); // blobs, hlcs and tombstones, byte for byte
    let items = a.list_items().unwrap();
    assert_eq!(items, b.list_items().unwrap());
    for i in &items {
        assert_eq!(a.get_login(&i.id).unwrap(), b.get_login(&i.id).unwrap());
    }

    // edits after a restore sort after everything restored, even with a stale clock
    let id = items[0].id.clone();
    b.save_login(Some(&id), &login("Edited", "new"), 1).unwrap();
    assert_eq!(b.get_login(&id).unwrap().title, "Edited");
}

#[test]
fn restore_with_the_recovery_code_and_verify() {
    let (a, code) = account();
    let file = a.backup(NOW + 10).unwrap();
    let info = verify_backup(&file, &BackupSecret::Recovery(&code), NOW).unwrap();
    assert_eq!(
        info,
        BackupInfo {
            created_ms: NOW + 10,
            items: 2
        }
    );
    let mut b = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Recovery(&code),
        NOW,
    )
    .unwrap();
    b.unlock(PW, NOW).unwrap();
    assert_eq!(b.list_items().unwrap().len(), 2);
}

#[test]
fn wrong_secret_is_refused() {
    let (a, _) = account();
    let file = a.backup(NOW).unwrap();
    for s in [
        BackupSecret::Password("not the master password!!"),
        BackupSecret::Recovery("nonsense"),
    ] {
        assert!(matches!(
            verify_backup(&file, &s, NOW),
            Err(AccountError::Crypto)
        ));
    }
}

#[test]
fn a_corrupted_backup_is_detected() {
    let (a, _) = account();
    let file = a.backup(NOW).unwrap();
    let pw = BackupSecret::Password(PW);

    // flip one bit in the header, early and late in the body, and the tag
    let header_end = 9 + u32::from_be_bytes(file[5..9].try_into().unwrap()) as usize;
    for at in [
        0,
        4,
        9,
        header_end / 2,
        header_end + 10,
        file.len() / 2,
        file.len() - 1,
    ] {
        let mut bad = file.clone();
        bad[at] ^= 1;
        assert!(verify_backup(&bad, &pw, NOW).is_err(), "flip at {at}");
    }
    // truncation, extension and garbage
    for bad in [
        &file[..file.len() - 1],
        &file[..8],
        &[][..],
        b"NSBK\x01\xff\xff\xff\xff",
    ] {
        assert!(verify_backup(bad, &pw, NOW).is_err());
    }
    let mut longer = file.clone();
    longer.push(0);
    assert!(verify_backup(&longer, &pw, NOW).is_err());
    // body corruption is reported as corruption, not as a wrong password
    let mut bad = file.clone();
    bad[file.len() - 1] ^= 1;
    assert!(matches!(
        verify_backup(&bad, &pw, NOW),
        Err(AccountError::BackupCorrupt)
    ));
}

#[test]
fn restore_never_overwrites_an_existing_vault() {
    let (a, _) = account();
    let file = a.backup(NOW).unwrap();
    let (b, _) = account();
    let store = b.store;
    assert!(matches!(
        Account::restore(store, &file, &BackupSecret::Password(PW), NOW),
        Err(AccountError::Format)
    ));
}

#[test]
fn backup_needs_unlock_and_schedule_follows_the_last_one() {
    let (mut a, _) = account();
    const DAY: u64 = 86_400_000;
    assert!(a.backup_due(NOW, DAY).unwrap());
    a.mark_backed_up(NOW).unwrap();
    assert!(!a.backup_due(NOW + DAY - 1, DAY).unwrap());
    assert!(a.backup_due(NOW + DAY, DAY).unwrap());
    a.lock();
    assert!(a.backup(NOW).is_err());
}
