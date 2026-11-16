#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;
// RFC 6238 test secret ("12345678901234567890"), base32
const RFC_SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const PW: &str = "correct horse battery staple 42!";

fn account() -> Account {
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    setup.confirm(&code, NOW).unwrap()
}

fn samples() -> Vec<ItemFields> {
    let base = |t| ItemFields {
        title: format!("{t:?}"),
        ..ItemFields::new(t)
    };
    vec![
        ItemFields {
            notes: "first line\nsecond".into(),
            ..base(ItemType::Note)
        },
        ItemFields {
            ssid: "Home".into(),
            security: "WPA3".into(),
            password: "correct horse".into(),
            ..base(ItemType::Wifi)
        },
        ItemFields {
            license_key: "AAAA-BBBB".into(),
            licensed_to: "Moritz".into(),
            ..base(ItemType::License)
        },
        ItemFields {
            codes: vec!["1111-2222".into(), "3333-4444".into()],
            ..base(ItemType::RecoveryCodes)
        },
        ItemFields {
            totp: format!("otpauth://totp/ACME:me?secret={RFC_SECRET}&digits=8"),
            ..base(ItemType::Totp)
        },
    ]
}

#[test]
fn each_type_is_created_edited_and_listed() {
    let mut a = account();
    for f in samples() {
        let id = a.save_item(None, &f, NOW + 1).unwrap();
        assert_eq!(a.get_item(&id).unwrap(), f);

        let edited = ItemFields {
            title: "renamed".into(),
            ..f.clone()
        };
        a.save_item(Some(&id), &edited, NOW + 2).unwrap();
        assert_eq!(a.get_item(&id).unwrap(), edited);

        let row = a
            .list_items()
            .unwrap()
            .into_iter()
            .find(|i| i.id == id)
            .unwrap();
        assert_eq!(
            (row.item_type, row.title.as_str()),
            (f.item_type, "renamed")
        );
    }
}

#[test]
fn clearing_a_field_and_blank_codes_are_not_stored() {
    let mut a = account();
    let f = samples().pop().unwrap();
    let id = a.save_item(None, &f, NOW + 1).unwrap();
    let cleared = ItemFields {
        codes: vec![" 3333-4444 ".into(), "  ".into(), String::new()],
        ..f
    };
    a.save_item(Some(&id), &cleared, NOW + 2).unwrap();
    assert_eq!(a.get_item(&id).unwrap().codes, ["3333-4444"]);
}

#[test]
fn a_type_cannot_change_and_login_is_not_an_item_field_type() {
    let mut a = account();
    let s = samples();
    let id = a.save_item(None, &s[0], NOW + 1).unwrap();
    assert!(matches!(
        a.save_item(Some(&id), &s[1], NOW + 2),
        Err(AccountError::Format)
    ));
    assert!(matches!(
        a.save_item(None, &ItemFields::new(ItemType::Login), NOW + 2),
        Err(AccountError::Format)
    ));
}

#[test]
fn only_logins_are_offered_to_web_pages() {
    let mut a = account();
    for f in samples() {
        a.save_item(None, &f, NOW + 1).unwrap();
    }
    assert!(a.login_candidates().unwrap().is_empty());
    assert_eq!(a.list_items().unwrap().len(), samples().len());
}

#[test]
fn totp_item_shows_the_reference_code_and_rejects_what_it_cannot_compute() {
    let mut a = account();
    let f = samples().pop().unwrap();
    let id = a.save_item(None, &f, NOW + 1).unwrap();
    // RFC 6238 appendix B: SHA-1, 8 digits, T = 59 s
    let c = a.login_totp(&id, 59_000).unwrap().unwrap();
    assert_eq!((&**c.code, c.remaining, c.period), ("94287082", 1, 30));

    for bad in [
        "",
        "not base32!",
        "steam://ABCDEFGH",
        &format!("otpauth://hotp/x?secret={RFC_SECRET}&counter=1"),
    ] {
        let f = ItemFields {
            totp: bad.into(),
            ..f.clone()
        };
        assert!(matches!(
            a.save_item(None, &f, NOW + 2),
            Err(AccountError::Format)
        ));
        assert!(matches!(
            a.save_item(Some(&id), &f, NOW + 2),
            Err(AccountError::Format)
        ));
    }
    // a bare secret is fine, and a secret on another item type is not stored
    let bare = ItemFields {
        totp: format!(" {RFC_SECRET} "),
        ..f.clone()
    };
    a.save_item(Some(&id), &bare, NOW + 3).unwrap();
    assert_eq!(a.get_item(&id).unwrap().totp, RFC_SECRET);
    let note = ItemFields {
        totp: RFC_SECRET.into(),
        ..ItemFields::new(ItemType::Note)
    };
    let nid = a.save_item(None, &note, NOW + 4).unwrap();
    assert_eq!(a.get_item(&nid).unwrap().totp, "");
}

// Google Authenticator export (see core-otp tests): two TOTP accounts, one HOTP, one MD5.
const MIGRATION: &str = "otpauth-migration://offline?data=Cj8KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhhBQ01FIENvOmpvaG5AZXhhbXBsZS5jb20aB0FDTUUgQ28gASgBMAIKLwogMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTISA2JvYhoAIAIoAjACCi4KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEglob3RwLWFjY3QaA09sZCABKAEwATgBCisKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEghtZDUtYWNjdBoDT2xkIAQoATACEAEYASAAKMDEBw%3D%3D";

#[test]
fn an_authenticator_export_becomes_one_entry_per_usable_account() {
    let mut a = account();
    let r = a.import_otp_migration(MIGRATION, NOW + 1).unwrap();
    assert_eq!((r.imported, r.skipped), (2, 2));

    let items = a.list_items().unwrap();
    let titles: Vec<_> = items.iter().map(|i| i.title.as_str()).collect();
    assert_eq!(titles, ["ACME Co (john@example.com)", "bob"]);
    assert!(items.iter().all(|i| i.item_type == ItemType::Totp));
    // RFC 6238 appendix B at T = 59 s
    let code = |i: usize| a.login_totp(&items[i].id, 59_000).unwrap().unwrap().code;
    assert_eq!((&**code(0), &**code(1)), ("287082", "46119246"));

    // damaged data, or another kind of link, creates nothing
    let before = a.list_items().unwrap().len();
    for bad in ["otpauth-migration://offline?data=AAA", "steam://ABCDEFGH"] {
        assert!(matches!(
            a.import_otp_migration(bad, NOW + 2),
            Err(AccountError::Otp(_))
        ));
    }
    assert_eq!(a.list_items().unwrap().len(), before);
}

#[test]
fn ssh_key_is_generated_stored_and_shown_with_public_key_and_fingerprint() {
    let mut a = account();
    for bits in [None, Some(2048)] {
        let private = generate_ssh_key(bits).unwrap();
        let (public, fingerprint) = ssh_key_info(&private).unwrap();
        let f = ItemFields {
            title: "deploy".into(),
            private_key: private.to_string(),
            ..ItemFields::new(ItemType::SshKey)
        };
        let id = a.save_item(None, &f, NOW + 1).unwrap();
        let got = a.get_item(&id).unwrap();
        assert_eq!(got.private_key, *private);
        assert!(fingerprint.starts_with("SHA256:"));
        assert_eq!((got.public_key, got.fingerprint), (public, fingerprint));

        // Editing keeps the key; the derived fields on the way in are ignored.
        let edited = ItemFields {
            title: "renamed".into(),
            public_key: "junk".into(),
            fingerprint: "junk".into(),
            ..f
        };
        a.save_item(Some(&id), &edited, NOW + 2).unwrap();
        let got = a.get_item(&id).unwrap();
        assert_eq!(got.title, "renamed");
        assert_eq!(got.private_key, *private);
        assert_ne!(got.fingerprint, "junk");
    }
}

#[test]
fn ssh_key_that_does_not_parse_is_refused_and_other_types_ignore_the_field() {
    let mut a = account();
    for bad in ["", "not a key", "ssh-ed25519 AAAA public line"] {
        let f = ItemFields {
            private_key: bad.into(),
            ..ItemFields::new(ItemType::SshKey)
        };
        assert!(matches!(
            a.save_item(None, &f, NOW + 1),
            Err(AccountError::Ssh(_))
        ));
    }
    assert!(matches!(
        generate_ssh_key(Some(512)),
        Err(AccountError::Ssh(core_ssh::Error::Unsupported))
    ));
    let note = ItemFields {
        private_key: "stray".into(),
        ..ItemFields::new(ItemType::Note)
    };
    let id = a.save_item(None, &note, NOW + 2).unwrap();
    assert_eq!(a.get_item(&id).unwrap().private_key, "");
}
