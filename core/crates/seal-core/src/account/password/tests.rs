#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";
const NEW_PW: &str = "tractor lemon orbit velvet 77?!";

fn params(t: u32) -> KdfParams {
    KdfParams::new(19 * 1024, t, 1).unwrap()
}

fn account() -> Account {
    account_with(2)
}

fn account_with(t: u32) -> Account {
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params(t)).unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    let f = LoginFields {
        title: "Bank".into(),
        username: "me".into(),
        password: "bank-pw".into(),
        url: String::new(),
        notes: String::new(),
    };
    a.save_login(None, &f, NOW + 1).unwrap();
    a
}

fn reopen(a: Account) -> Account {
    Account::open(a.store).unwrap().unwrap()
}

#[test]
fn change_keeps_the_vault_and_retires_the_old_password() {
    let mut a = account();
    let before = a.list_items().unwrap();
    let records = a.store.list(a.vault_id().unwrap()).unwrap();
    a.change_password(PW, NEW_PW, params(2)).unwrap();

    let mut a = reopen(a); // from what was persisted
    assert!(a.unlock(PW, NOW + 2).is_err(), "old password must not work");
    a.unlock(NEW_PW, NOW + 3).unwrap();
    assert_eq!(a.list_items().unwrap(), before);
    assert_eq!(a.store.list(a.vault_id().unwrap()).unwrap(), records); // not re-encrypted
}

#[test]
fn upgrade_raises_the_stored_kdf_and_uses_a_fresh_salt() {
    let mut a = account();
    let salt = a.meta.shared.salt.clone();
    a.change_password(PW, PW, params(3)).unwrap(); // same password, stronger KDF
    assert_ne!(a.meta.shared.salt, salt);
    assert_eq!(a.meta.shared.kdf, [19 * 1024, 3, 1]);
    let mut a = reopen(a);
    a.unlock(PW, NOW + 2).unwrap();
}

#[test]
fn refused_changes_leave_everything_as_it_was() {
    let mut a = account();
    assert!(
        a.change_password("wrong password here!", NEW_PW, params(2))
            .is_err()
    );
    assert!(matches!(
        a.change_password(PW, "short", params(2)),
        Err(AccountError::WeakPassword)
    ));
    let mut strong = account_with(3);
    assert!(
        strong.change_password(PW, NEW_PW, params(2)).is_err(),
        "no downgrade"
    );
    a.lock();
    assert!(
        a.change_password(PW, NEW_PW, params(2)).is_err(),
        "needs unlock"
    );

    let mut a = reopen(a);
    a.unlock(PW, NOW + 2).unwrap();
}
