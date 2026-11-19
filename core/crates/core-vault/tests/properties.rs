//! Property tests for item encryption (#30): any item round-trips, and any single-bit
//! change to the sealed blob or its bound context is rejected.

#![allow(clippy::unwrap_used)]

use core_crypto::Key;
use core_vault::{Item, Payload, RecordContext, Url, open_item, seal_item};
use proptest::prelude::*;
use serde_json::{Map, Value};

fn json_value() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::from),
        any::<i64>().prop_map(Value::from),
        any::<u64>().prop_map(Value::from),
        any::<String>().prop_map(Value::from),
    ];
    leaf.prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            prop::collection::btree_map("[a-z]{1,6}", inner, 0..4)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Unknown keys are prefixed so they can never collide with a modelled field name.
fn unknown() -> impl Strategy<Value = Map<String, Value>> {
    prop::collection::btree_map("x_[a-z]{1,6}", json_value(), 0..3)
        .prop_map(|m| m.into_iter().collect())
}

fn opt_string() -> impl Strategy<Value = Option<String>> {
    prop::option::of(any::<String>())
}

fn url() -> impl Strategy<Value = Url> {
    (any::<String>(), opt_string(), unknown()).prop_map(|(url, m, unknown)| Url {
        url,
        r#match: m,
        unknown,
    })
}

fn item() -> impl Strategy<Value = Item> {
    (
        (any::<String>(), opt_string(), any::<bool>(), opt_string()),
        (prop::collection::vec(any::<String>(), 0..4), any::<bool>()),
        (any::<u64>(), any::<u64>(), prop::option::of(any::<u64>())),
        (opt_string(), opt_string(), opt_string()),
        (prop::collection::vec(url(), 0..3), unknown()),
        (opt_string(), opt_string(), opt_string(), opt_string()),
        prop::collection::vec(any::<String>(), 0..4),
        opt_string(),
    )
        .prop_map(
            |(
                (title, notes, favorite, folder),
                (tags, reprompt),
                (c, u, d),
                (user, pw, totp),
                (urls, unknown),
                (ssid, wifi_security, license_key, licensed_to),
                codes,
                private_key,
            )| Item {
                title,
                notes,
                favorite,
                folder,
                tags,
                reprompt,
                created_at: c,
                updated_at: u,
                deleted_at: d,
                username: user,
                password: pw,
                totp,
                urls,
                ssid,
                wifi_security,
                license_key,
                licensed_to,
                codes,
                private_key,
                unknown,
            },
        )
}

fn payload() -> impl Strategy<Value = Payload> {
    (
        item(),
        unknown(),
        prop::collection::btree_map("[a-z]{1,6}", "[0-9a-f]{24}", 0..3),
        unknown(),
    )
        .prop_map(|(data, extras, fields_hlc, unknown)| {
            let mut p = Payload::new_login(data);
            p.extras = extras;
            p.fields_hlc = fields_hlc;
            p.unknown = unknown;
            p
        })
}

fn ctx<'a>(vault: &'a str, id: &'a str, hlc: &'a str, tombstone: bool) -> RecordContext<'a> {
    RecordContext {
        vault_id: vault.as_bytes(),
        record_id: id.as_bytes(),
        hlc,
        tombstone,
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn any_item_round_trips(
        p in payload(), kb in any::<[u8; 32]>(), gen_ in any::<u32>(),
        vault in "[a-z0-9-]{1,12}", id in r"\PC{1,16}", hlc in "[0-9a-f]{24}", tomb in any::<bool>(),
    ) {
        let key = Key::from_bytes(kb);
        let c = ctx(&vault, &id, &hlc, tomb);
        let blob = seal_item(&key, gen_, &c, &p).unwrap();
        let (g, back) = open_item(&key, &c, &blob).unwrap();
        prop_assert_eq!(g, gen_);
        prop_assert_eq!(back, p);
    }

    #[test]
    fn any_bit_flip_or_context_change_is_rejected(
        p in payload(), kb in any::<[u8; 32]>(), bit in any::<usize>(),
        id in "[a-z0-9]{1,8}", hlc in "[0-9a-f]{24}",
    ) {
        let key = Key::from_bytes(kb);
        let c = ctx("v", &id, &hlc, false);
        let blob = seal_item(&key, 0, &c, &p).unwrap();

        let mut t = blob.clone();
        let bit = bit % (t.len() * 8);
        t[bit / 8] ^= 1 << (bit % 8);
        prop_assert!(open_item(&key, &c, &t).is_err());

        let other_id = format!("{id}x");
        prop_assert!(open_item(&key, &ctx("v", &other_id, &hlc, false), &blob).is_err());
        prop_assert!(open_item(&key, &ctx("v", &id, &hlc, true), &blob).is_err());
        let mut other_key = kb;
        other_key[0] ^= 1;
        prop_assert!(open_item(&Key::from_bytes(other_key), &c, &blob).is_err());
    }
}
