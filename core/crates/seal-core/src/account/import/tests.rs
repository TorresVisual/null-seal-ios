#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";
const EXPORT: &[u8] = include_bytes!("../../../../../tests/fixtures/bitwarden/unencrypted.json");
const ENCRYPTED: &[u8] =
    include_bytes!("../../../../../tests/fixtures/bitwarden/password-protected.json");

const CSV: &[u8] = include_bytes!("../../../../../tests/fixtures/bitwarden/unencrypted.csv");

fn account() -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    setup.confirm(&code, NOW).unwrap()
}

#[test]
fn imports_then_reimport_changes_nothing() {
    let mut a = account();
    let first = a.import_bitwarden(EXPORT, NOW + 1).unwrap();
    assert_eq!((first.imported, first.already_present), (13, 0));
    let listed = a.list_items().unwrap();
    assert_eq!(listed.len(), 13);
    assert!(listed.iter().any(|i| i.title == "Example Mail"));

    let second = a.import_bitwarden(EXPORT, NOW + 2).unwrap();
    assert_eq!((second.imported, second.already_present), (0, 13));
    assert_eq!(a.list_items().unwrap(), listed);
}

#[test]
fn reimport_keeps_edits_and_does_not_resurrect_deletes() {
    let mut a = account();
    a.import_bitwarden(EXPORT, NOW + 1).unwrap();
    let items = a.list_items().unwrap();
    let mail = items.iter().find(|i| i.title == "Example Mail").unwrap();
    let mut f = a.get_login(&mail.id).unwrap();
    f.title = "Renamed".into();
    a.save_login(Some(&mail.id), &f, NOW + 2).unwrap();
    let steam = items
        .iter()
        .find(|i| i.title == "Steam style code")
        .unwrap();
    a.delete_login(&steam.id, NOW + 3).unwrap();

    let again = a.import_bitwarden(EXPORT, NOW + 4).unwrap();
    assert_eq!(again.imported, 0);
    let titles: Vec<_> = a
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert!(titles.contains(&"Renamed".to_owned()));
    assert!(!titles.contains(&"Example Mail".to_owned()));
    assert!(!titles.contains(&"Steam style code".to_owned()));
}

#[test]
fn imported_login_is_usable() {
    let mut a = account();
    a.import_bitwarden(EXPORT, NOW + 1).unwrap();
    let items = a.list_items().unwrap();
    let mail = items.iter().find(|i| i.title == "Example Mail").unwrap();
    let f = a.get_login(&mail.id).unwrap();
    assert_eq!(f.username, "synthetic.user@example.com");
    assert_eq!(f.url, "https://mail.example.com/login");
    assert!(a.login_totp(&mail.id, NOW).unwrap().is_some());
}

#[test]
fn refuses_encrypted_and_garbage_without_writing() {
    let mut a = account();
    assert!(matches!(
        a.import_bitwarden(ENCRYPTED, NOW + 1),
        Err(AccountError::ImportPasswordRequired)
    ));
    assert!(matches!(
        a.import_bitwarden_password(ENCRYPTED, "wrong", NOW + 1),
        Err(AccountError::ImportWrongPassword)
    ));
    assert!(matches!(
        a.import_bitwarden(b"not json", NOW + 1),
        Err(AccountError::Format)
    ));
    assert!(a.list_items().unwrap().is_empty());
}

#[test]
fn password_protected_export_imports_like_plaintext() {
    let mut a = account();
    let s = a
        .import_bitwarden_password(ENCRYPTED, "synthetic-export-password", NOW + 1)
        .unwrap();
    assert_eq!((s.imported, s.already_present), (13, 0));
    // Same record ids as the plaintext import: importing both changes nothing the second time.
    let s = a.import_bitwarden(EXPORT, NOW + 2).unwrap();
    assert_eq!((s.imported, s.already_present), (0, 13));
}

#[test]
fn csv_imports_and_reimport_changes_nothing() {
    let mut a = account();
    let first = a.import_bitwarden_csv(CSV, NOW + 1).unwrap();
    assert_eq!((first.imported, first.already_present), (3, 0));
    let listed = a.list_items().unwrap();
    assert!(listed.iter().any(|i| i.title == "Home Wi-Fi"));
    let second = a.import_bitwarden_csv(CSV, NOW + 2).unwrap();
    assert_eq!((second.imported, second.already_present), (0, 3));
    assert_eq!(a.list_items().unwrap(), listed);
}

#[test]
fn locked_account_cannot_import() {
    let mut a = account();
    a.lock();
    assert!(a.import_bitwarden(EXPORT, NOW + 1).is_err());
}
