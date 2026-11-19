#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

fn new_account() -> (Account, String) {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let a = setup.confirm(&code, NOW).unwrap();
    (a, code.to_string())
}

/// An account with a rich item (every field), a plain one and a deleted one.
fn account() -> Account {
    let (mut a, _) = new_account();
    let f = |t: &str, pw: &str| LoginFields {
        title: t.into(),
        username: "me@example.com".into(),
        password: pw.into(),
        url: "https://example.com".into(),
        notes: "note".into(),
    };
    let rich = a.save_login(None, &f("Rich", "pw-1"), NOW + 1).unwrap();
    a.save_login(Some(&rich), &f("Rich", "pw-2"), NOW + 2)
        .unwrap();
    let mut p = a.session.open_record(&a.live(&rich).unwrap()).unwrap();
    p.data.tags = vec!["work".into(), "ünï".into()];
    p.data.totp = Some("JBSWY3DPEHPK3PXP".into());
    p.data.folder = Some("a/b".into());
    p.extras
        .insert("source".into(), serde_json::json!({"k": [1, 2]}));
    p.data.unknown.insert("future".into(), "kept".into());
    let old = a.session.open_record(&a.live(&rich).unwrap()).unwrap();
    a.write(&rich, Some(&old), Some(p), NOW + 3).unwrap();
    a.save_login(None, &f("Plain", "pw-3"), NOW + 4).unwrap();
    let gone = a.save_login(None, &f("Gone", "pw-4"), NOW + 5).unwrap();
    a.delete_login(&gone, NOW + 6).unwrap();
    a
}

fn payloads(a: &Account) -> Vec<(String, Payload)> {
    let mut v: Vec<_> = a
        .store
        .list(a.vault_id().unwrap())
        .unwrap()
        .iter()
        .filter(|r| !r.tombstone)
        .map(|r| {
            let mut p = a.session.open_record(r).unwrap();
            p.fields_hlc.clear();
            p.history.clear();
            (r.id.clone(), p)
        })
        .collect();
    v.sort_by(|x, y| x.0.cmp(&y.0));
    v
}

#[test]
fn plaintext_export_needs_the_master_password() {
    let mut a = account();
    for wrong in [
        "",
        "wrong password here!",
        "correct horse battery staple 42",
    ] {
        assert!(a.export_plaintext(wrong, NOW + 10).is_err());
    }
    a.lock();
    assert!(a.export_plaintext(PW, NOW + 10).is_err(), "needs unlock");
    a.unlock(PW, NOW + 11).unwrap();
    let e = a.export_plaintext(PW, NOW + 12).unwrap();
    assert_eq!((e.items, e.skipped), (2, 0), "deleted items are left out");
    assert!(String::from_utf8_lossy(&e.json).contains("pw-2"));
}

#[test]
fn an_export_reimports_into_a_fresh_vault_unchanged() {
    let a = account();
    let json = a.export_plaintext(PW, NOW + 10).unwrap().json;

    let (mut b, _) = new_account();
    assert_eq!(b.import_plaintext(&json, NOW + 20).unwrap(), 2);
    assert_eq!(payloads(&a), payloads(&b)); // every field, extras and unknown keys included
    let titles: Vec<_> = b
        .list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect();
    assert_eq!(titles, ["Plain", "Rich"]);

    // the same file again, and into the exporting vault itself: updates in place, no duplicates
    assert_eq!(b.import_plaintext(&json, NOW + 30).unwrap(), 2);
    let mut a = a;
    a.import_plaintext(&json, NOW + 31).unwrap();
    assert_eq!(payloads(&a), payloads(&b));
    assert_eq!(b.list_items().unwrap().len(), 2);
}

#[test]
fn bad_imports_change_nothing() {
    let (mut a, _) = new_account();
    let ok = account().export_plaintext(PW, NOW).unwrap().json;
    let text = String::from_utf8(ok.to_vec()).unwrap();
    for bad in [
        "not json".to_owned(),
        text.replace("null-seal-export", "other"),
        text.replace(
            "\"version\": 1,\n  \"exported",
            "\"version\": 9,\n  \"exported",
        ),
        text.replacen("\"v\": 1", "\"v\": 7", 1), // an item from a newer schema
    ] {
        assert!(a.import_plaintext(bad.as_bytes(), NOW + 1).is_err());
        assert!(a.list_items().unwrap().is_empty());
    }
}
