#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn account() -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    setup.confirm(&code, NOW).unwrap()
}

fn reopen(a: Account) -> Account {
    Account::open(a.store).unwrap().unwrap()
}

#[test]
fn the_device_key_unlocks_and_nothing_else_does() {
    let mut a = account();
    assert!(!a.device_unlock_enabled());
    let key = Key::random().unwrap();
    a.enable_device_unlock(&key).unwrap();

    let mut a = reopen(a); // from what was persisted
    assert!(a.device_unlock_enabled());
    assert!(matches!(
        a.unlock_with_device_key(&Key::random().unwrap(), NOW + 1),
        Err(AccountError::Session(SessionError::Crypto))
    ));
    assert_eq!(a.state(), State::Locked);
    a.unlock_with_device_key(&key, NOW + 1_000_000).unwrap(); // past the failed-attempt delay
    assert_eq!(a.state(), State::Unlocked);
    assert!(a.list_items().unwrap().is_empty());
}

#[test]
fn it_needs_an_unlocked_account_and_an_enabled_wrapper() {
    let mut a = account();
    let key = Key::random().unwrap();
    assert!(matches!(
        a.unlock_with_device_key(&key, NOW + 1),
        Err(AccountError::NoDeviceUnlock)
    ));
    a.lock();
    assert!(
        a.enable_device_unlock(&key).is_err(),
        "no Account Key to wrap while locked"
    );
    assert!(!a.device_unlock_enabled());
}

#[test]
fn disabling_works_locked_and_leaves_the_password_working() {
    let mut a = account();
    let key = Key::random().unwrap();
    a.enable_device_unlock(&key).unwrap();
    a.lock();
    a.disable_device_unlock().unwrap();

    let mut a = reopen(a);
    assert!(!a.device_unlock_enabled());
    assert!(a.unlock_with_device_key(&key, NOW + 1).is_err());
    a.unlock(PW, NOW + 2).unwrap();
}

#[test]
fn a_password_change_keeps_it_and_it_is_never_shared() {
    let mut a = account();
    let key = Key::random().unwrap();
    a.enable_device_unlock(&key).unwrap();
    let new_pw = "tractor lemon orbit velvet 77?!";
    a.change_password(PW, new_pw, KdfParams::new(19 * 1024, 2, 1).unwrap())
        .unwrap();
    a.lock();
    a.unlock_with_device_key(&key, NOW + 1).unwrap();
    // the wrapper is local metadata: never part of what other devices receive
    assert!(a.meta.device_wrapper.is_some());
    assert!(
        !serde_json::to_string(&a.meta.shared)
            .unwrap()
            .contains("device_wrapper")
    );
}
