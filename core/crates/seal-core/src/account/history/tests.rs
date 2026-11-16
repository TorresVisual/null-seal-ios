#![allow(clippy::unwrap_used)]

use super::*;
use core_vault::HISTORY_MAX;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn login(password: &str) -> LoginFields {
    LoginFields {
        title: "Bank".into(),
        username: "me".into(),
        password: password.into(),
        url: "https://bank.example".into(),
        notes: String::new(),
    }
}

fn account() -> (Account, String) {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    let id = a.save_login(None, &login("v0"), NOW + 1).unwrap();
    (a, id)
}

#[test]
fn an_overwritten_password_stays_restorable() {
    let (mut a, id) = account();
    assert!(a.item_history(&id).unwrap().is_empty());
    a.save_login(Some(&id), &login("v1"), NOW + 2).unwrap();

    let h = a.item_history(&id).unwrap();
    assert_eq!(h.len(), 1);
    assert_eq!(h[0].fields.password, "v0");

    a.restore_version(&id, &h[0].at, NOW + 3).unwrap();
    assert_eq!(a.get_login(&id).unwrap(), login("v0"));
    // the restore is itself undoable: v1 is now in the history
    let h = a.item_history(&id).unwrap();
    assert_eq!(h[0].fields.password, "v1");
}

#[test]
fn unchanged_saves_and_unknown_versions_add_nothing() {
    let (mut a, id) = account();
    a.save_login(Some(&id), &login("v0"), NOW + 2).unwrap(); // only updated_at moves
    assert!(a.item_history(&id).unwrap().is_empty());
    assert!(matches!(
        a.restore_version(&id, "nope", NOW + 3),
        Err(AccountError::NotFound)
    ));
}

#[test]
fn retention_limit_keeps_the_newest() {
    let (mut a, id) = account();
    for i in 1..=HISTORY_MAX + 5 {
        a.save_login(Some(&id), &login(&format!("v{i}")), NOW + 1 + i as u64)
            .unwrap();
    }
    let h = a.item_history(&id).unwrap();
    assert_eq!(h.len(), HISTORY_MAX);
    assert_eq!(h[0].fields.password, format!("v{}", HISTORY_MAX + 4)); // newest first
    assert_eq!(h[HISTORY_MAX - 1].fields.password, "v5"); // v0..v4 fell off
}
