#![allow(clippy::unwrap_used)]

use super::*;
use core_keys::{ENVELOPE_VERSION, SUITE};
use serde_json::json;

const HLC: &str = "00000000000100000000abcd";

fn ctx() -> RecordContext<'static> {
    RecordContext {
        vault_id: b"vault-1",
        record_id: b"item-1",
        hlc: HLC,
        tombstone: false,
    }
}

fn vk() -> Key {
    Key::from_bytes([7; 32])
}

fn login() -> Payload {
    Payload::new_login(Item {
        title: "Example".into(),
        username: Some("moritz".into()),
        password: Some("hunter2 \u{1f510}".into()),
        urls: vec![Url {
            url: "https://example.com".into(),
            r#match: None,
            unknown: Map::new(),
        }],
        tags: vec!["a".into()],
        created_at: 1,
        updated_at: 2,
        ..Item::default()
    })
}

/// Encrypt arbitrary JSON the way `seal_item` does, to forge "newer client" records.
fn seal_json(v: &Value) -> Vec<u8> {
    let mut pt = serde_json::to_vec(v).unwrap();
    pt.push(0x80);
    pt.resize(pt.len().next_multiple_of(PAD_BLOCK), 0);
    seal(&vk(), 0, &ctx().aad(), &pt).unwrap()
}

#[test]
fn round_trips() {
    let p = login();
    let blob = seal_item(&vk(), 5, &ctx(), &p).unwrap();
    let (gen_, back) = open_item(&vk(), &ctx(), &blob).unwrap();
    assert_eq!((gen_, back), (5, p));
}

#[test]
fn every_item_type_round_trips_with_its_wire_name() {
    let s = |v: &str| Some(v.to_owned());
    let cases = [
        (
            ItemType::Note,
            "note",
            Item {
                title: "Plan".into(),
                notes: s("the \"body\"\nline two"),
                ..Item::default()
            },
        ),
        (
            ItemType::Wifi,
            "wifi",
            Item {
                title: "Home".into(),
                ssid: s("Büro-5G"),
                wifi_security: s("WPA3"),
                password: s("correct horse"),
                ..Item::default()
            },
        ),
        (
            ItemType::License,
            "license",
            Item {
                title: "Editor".into(),
                license_key: s("AAAA-BBBB-CCCC"),
                licensed_to: s("Moritz"),
                ..Item::default()
            },
        ),
        (
            ItemType::RecoveryCodes,
            "recovery_codes",
            Item {
                title: "Example account".into(),
                codes: vec!["1111-2222".into(), "3333-4444".into()],
                ..Item::default()
            },
        ),
        (
            ItemType::Totp,
            "totp",
            Item {
                title: "ACME".into(),
                totp: s("otpauth://totp/ACME:me?secret=GEZDGNBV"),
                ..Item::default()
            },
        ),
    ];
    for (ty, name, data) in cases {
        let p = Payload::new(ty, data);
        assert_eq!(serde_json::to_value(&p).unwrap()["type"], name);
        let blob = seal_item(&vk(), 0, &ctx(), &p).unwrap();
        assert_eq!(open_item(&vk(), &ctx(), &blob).unwrap().1, p, "{name}");
    }
}

#[test]
fn schema_version_is_explicit_and_checked() {
    let json = serde_json::to_value(login()).unwrap();
    assert_eq!(json["v"], 1);
    assert_eq!(json["kind"], "item");
    assert_eq!(json["type"], "login");

    let mut newer = json.clone();
    newer["v"] = json!(2);
    let blob = seal_json(&newer);
    assert_eq!(open_item(&vk(), &ctx(), &blob), Err(VaultError::Version(2)));
    // even if the newer payload no longer fits our structs
    let blob = seal_json(&json!({"v": 3, "kind": "card_vault", "stuff": [1]}));
    assert_eq!(open_item(&vk(), &ctx(), &blob), Err(VaultError::Version(3)));

    for bad in [json!({"kind":"item"}), json!({"v":"1"})] {
        assert_eq!(
            open_item(&vk(), &ctx(), &seal_json(&bad)),
            Err(VaultError::Format)
        );
    }
    let mut zero = json;
    zero["v"] = json!(0);
    assert_eq!(
        open_item(&vk(), &ctx(), &seal_json(&zero)),
        Err(VaultError::Version(0))
    );
}

#[test]
fn unknown_fields_survive_a_round_trip_at_every_level() {
    let blob = seal_json(&json!({
        "v": 1, "kind": "item", "type": "login",
        "future_top": {"x": [1, 2]},
        "fields_hlc": {"password": HLC},
        "extras": {"bitwarden": {"type": 1}},
        "data": {
            "title": "t", "password": "p", "future_item": 42,
            "urls": [{"url": "https://a", "match": "regex2", "future_url": true}]
        }
    }));
    let (_, p) = open_item(&vk(), &ctx(), &blob).unwrap();
    assert_eq!(p.unknown["future_top"], json!({"x": [1, 2]}));
    assert_eq!(p.data.unknown["future_item"], 42);
    assert_eq!(p.data.urls[0].unknown["future_url"], true);
    assert_eq!(p.data.urls[0].r#match.as_deref(), Some("regex2"));

    // an edit by this client writes everything back
    let mut p = p;
    p.data.title = "edited".into();
    let (_, again) = open_item(&vk(), &ctx(), &seal_item(&vk(), 0, &ctx(), &p).unwrap()).unwrap();
    assert_eq!(again, p);
    let v = serde_json::to_value(&again).unwrap();
    assert_eq!(v["future_top"], json!({"x": [1, 2]}));
    assert_eq!(v["extras"]["bitwarden"]["type"], 1);
    assert_eq!(v["data"]["future_item"], 42);
    assert_eq!(v["data"]["urls"][0]["future_url"], true);
    assert_eq!(v["data"]["title"], "edited");
}

#[test]
fn unknown_kind_or_type_is_a_format_error_not_a_guess() {
    for bad in [
        json!({"v":1,"kind":"item","type":"card","data":{}}),
        json!({"v":1,"kind":"folder","type":"login","data":{}}),
    ] {
        assert_eq!(
            open_item(&vk(), &ctx(), &seal_json(&bad)),
            Err(VaultError::Format)
        );
    }
}

#[test]
fn tampering_with_ciphertext_is_rejected_at_every_byte() {
    let blob = seal_item(&vk(), 0, &ctx(), &login()).unwrap();
    for i in 0..blob.len() {
        let mut t = blob.clone();
        t[i] ^= 1;
        assert_eq!(
            open_item(&vk(), &ctx(), &t),
            Err(VaultError::Crypto),
            "flip at byte {i} accepted"
        );
    }
    assert!(open_item(&vk(), &ctx(), &blob[..blob.len() - 1]).is_err());
    assert!(open_item(&vk(), &ctx(), &[]).is_err());
}

#[test]
fn id_revision_vault_and_tombstone_are_bound() {
    let blob = seal_item(&vk(), 0, &ctx(), &login()).unwrap();
    let c = ctx();
    let others = [
        RecordContext {
            record_id: b"item-2",
            ..c
        },
        RecordContext {
            vault_id: b"vault-2",
            ..c
        },
        RecordContext {
            hlc: "00000000000100000000abce",
            ..c
        },
        RecordContext {
            tombstone: true,
            ..c
        },
    ];
    for o in &others {
        assert_eq!(open_item(&vk(), o, &blob), Err(VaultError::Crypto), "{o:?}");
    }
    assert_eq!(
        open_item(&Key::from_bytes([8; 32]), &c, &blob),
        Err(VaultError::Crypto)
    );
}

#[test]
fn unknown_envelope_version_is_rejected() {
    let mut blob = seal_item(&vk(), 0, &ctx(), &login()).unwrap();
    assert_eq!((blob[0], blob[1]), (ENVELOPE_VERSION, SUITE));
    blob[0] = 2;
    assert!(open_item(&vk(), &ctx(), &blob).is_err());
}

#[test]
fn plaintext_is_padded_to_blocks_hiding_exact_length() {
    let overhead = 6 + 24 + 16; // envelope header + nonce + tag
    let mut sizes = std::collections::BTreeSet::new();
    for n in [1, 2, 8] {
        let mut p = login();
        p.data.notes = Some("x".repeat(n));
        let blob = seal_item(&vk(), 0, &ctx(), &p).unwrap();
        assert_eq!((blob.len() - overhead) % PAD_BLOCK, 0);
        sizes.insert(blob.len());
    }
    assert_eq!(sizes.len(), 1, "small edits must not change the blob size");
}

#[test]
fn bad_padding_is_a_format_error() {
    let seal_raw = |pt: &[u8]| seal(&vk(), 0, &ctx().aad(), pt).unwrap();
    for pt in [&b""[..], &[0u8; 256][..], &b"{}"[..]] {
        assert_eq!(
            open_item(&vk(), &ctx(), &seal_raw(pt)),
            Err(VaultError::Format)
        );
    }
}
