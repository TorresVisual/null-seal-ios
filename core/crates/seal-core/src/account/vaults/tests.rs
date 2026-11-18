#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn account() -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    setup.confirm(&code, NOW).unwrap()
}

fn login(title: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me".into(),
        password: "hunter2".into(),
        url: "https://example.com".into(),
        notes: String::new(),
    }
}

fn titles(a: &Account) -> Vec<String> {
    a.list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect()
}

#[test]
fn a_new_vault_starts_empty_is_named_and_becomes_active() {
    let mut a = account();
    let personal = a.list_vaults().unwrap()[0].id.clone();
    a.save_login(None, &login("bank"), NOW).unwrap();

    let work = a.create_vault("  Work ").unwrap();
    let vaults = a.list_vaults().unwrap();
    assert_eq!(
        vaults.iter().map(|v| v.name.as_str()).collect::<Vec<_>>(),
        ["Personal", "Work"]
    );
    assert!(vaults[1].active && !vaults[0].active);
    assert!(titles(&a).is_empty());

    a.select_vault(&personal).unwrap();
    assert_eq!(titles(&a), ["bank"]);
    assert!(a.select_vault("nope").is_err());
    assert!(a.create_vault("   ").is_err());
    assert!(a.create_vault(&"x".repeat(65)).is_err());
    assert_ne!(personal, work);
}

#[test]
fn vaults_are_isolated_in_listing_autofill_search_and_by_id() {
    let mut a = account();
    let personal = a.list_vaults().unwrap()[0].id.clone();
    let bank = a.save_login(None, &login("bank"), NOW).unwrap();

    let work = a.create_vault("Work").unwrap();
    let vpn = a.save_login(None, &login("vpn"), NOW + 1).unwrap();
    assert_eq!(titles(&a), ["vpn"]);
    assert_eq!(a.login_candidates().unwrap().len(), 1);
    assert_eq!(a.session.search(&work, "bank").unwrap().len(), 0);
    // an id of the other vault is unreachable, whatever the client asks
    assert!(matches!(a.get_login(&bank), Err(AccountError::NotFound)));
    assert!(matches!(
        a.delete_login(&bank, NOW + 2),
        Err(AccountError::NotFound)
    ));

    a.select_vault(&personal).unwrap();
    assert_eq!(titles(&a), ["bank"]);
    assert!(matches!(a.get_login(&vpn), Err(AccountError::NotFound)));
    assert_eq!(a.session.search(&personal, "vpn").unwrap().len(), 0);
}

#[test]
fn each_vault_has_its_own_key() {
    let mut a = account();
    let personal = a.list_vaults().unwrap()[0].id.clone();
    let bank = a.save_login(None, &login("bank"), NOW).unwrap();
    let work = a.create_vault("Work").unwrap();

    // the record relabelled into the other vault does not open: wrong key and wrong context
    let mut rec = a.store.get(&bank).unwrap().unwrap();
    assert_eq!(rec.vault, personal);
    rec.vault = work;
    assert!(a.session.open_record(&rec).is_err());
}

#[test]
fn moving_re_encrypts_under_the_target_key_and_removes_the_original() {
    let mut a = account();
    let personal = a.list_vaults().unwrap()[0].id.clone();
    let id = a.save_login(None, &login("vpn"), NOW).unwrap();
    let work = a.create_vault("Work").unwrap();
    a.select_vault(&personal).unwrap();

    let new_id = a.move_item(&id, &work, NOW + 1).unwrap();
    assert_ne!(new_id, id);
    assert!(titles(&a).is_empty()); // gone from the source...
    let old = a.store.get(&id).unwrap().unwrap();
    assert!(old.tombstone && old.vault == personal);

    a.select_vault(&work).unwrap(); // ...present in the target, readable under its key only
    assert_eq!(titles(&a), ["vpn"]);
    assert_eq!(a.get_login(&new_id).unwrap(), login("vpn"));
    let moved = a.store.get(&new_id).unwrap().unwrap();
    assert_eq!(moved.vault, work);
    let mut relabelled = moved.clone();
    relabelled.vault = personal.clone();
    assert!(a.session.open_record(&relabelled).is_err());

    // both writes are queued for the relay
    let pending: Vec<_> = a
        .store
        .pending()
        .unwrap()
        .into_iter()
        .map(|(r, _)| r.id)
        .collect();
    assert!(pending.contains(&id) && pending.contains(&new_id));

    // nothing to move into the same vault, an unknown vault, or an item that is not here
    assert!(a.move_item(&new_id, &work, NOW + 2).is_err());
    assert!(a.move_item(&new_id, "nope", NOW + 2).is_err());
    assert!(a.move_item(&id, &personal, NOW + 2).is_err());
}

#[test]
fn locking_resets_the_selection_and_hides_the_vaults() {
    let mut a = account();
    let personal = a.list_vaults().unwrap()[0].id.clone();
    a.create_vault("Work").unwrap();
    a.lock();
    assert!(a.list_vaults().is_err());
    assert!(a.select_vault(&personal).is_err());
    assert!(a.create_vault("Again").is_err());

    a.unlock(PW, NOW + 1).unwrap();
    let vaults = a.list_vaults().unwrap();
    assert_eq!(vaults.len(), 2);
    assert!(vaults[0].active); // back on the first vault
    assert_eq!(vaults[1].name, "Work"); // the name survives, sealed in the saved metadata
}
