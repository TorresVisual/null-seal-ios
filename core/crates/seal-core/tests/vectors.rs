//! Shared test vectors (`core/tests/vectors/v1.json`): the byte-level contract that every
//! platform (Rust here, WASM and Swift later) must reproduce. Each entry is decrypted or
//! decoded and compared; negative entries must be rejected. The file is frozen: it is only
//! regenerated when the format changes, with
//! `cargo test -p seal-core --test vectors -- --ignored regenerate`.

#![allow(clippy::unwrap_used)]

use core_crypto::{KdfParams, Key};
use core_keys::{
    MasterHeader, PW_NORM, RecoveryError, Wrapper, decode_recovery_key, encode_recovery_key,
    unwrap_account_key, wrap_account_key,
};
use core_vault::{Item, Payload, RecordContext, Url, open_item, seal_item};
use serde_json::{Value, json};

const FILE: &str = include_str!("../../../tests/vectors/v1.json");
const PATH: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/v1.json");

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key(v: &Value) -> Key {
    Key::from_bytes(unhex(v.as_str().unwrap()).try_into().unwrap())
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn wrapper_of<'a>(v: &'a Value, hdr: &'a Option<MasterHeader>, k: &'a Option<Key>) -> Wrapper<'a> {
    match s(&v["kind"]) {
        "master" => Wrapper::Master {
            password: s(&v["password"]),
            header: hdr.as_ref().unwrap(),
        },
        "recovery" => Wrapper::Recovery(k.as_ref().unwrap()),
        "device" => Wrapper::Device {
            key: k.as_ref().unwrap(),
            device_id: s(&v["device_id"]).as_bytes(),
        },
        other => panic!("unknown wrapper kind {other}"),
    }
}

fn header_of(v: &Value) -> Option<MasterHeader> {
    (v["kind"] == "master").then(|| MasterHeader {
        salt: unhex(s(&v["salt"])).try_into().unwrap(),
        params: KdfParams::new(
            v["m_kib"].as_u64().unwrap().try_into().unwrap(),
            v["t"].as_u64().unwrap().try_into().unwrap(),
            v["p"].as_u64().unwrap().try_into().unwrap(),
        )
        .unwrap(),
        pw_norm: v["pw_norm"].as_u64().unwrap().try_into().unwrap(),
    })
}

fn open_record(v: &Value) -> Result<Payload, core_vault::VaultError> {
    let ctx = RecordContext {
        vault_id: s(&v["vault"]).as_bytes(),
        record_id: s(&v["record"]).as_bytes(),
        hlc: s(&v["hlc"]),
        tombstone: v["tombstone"].as_bool().unwrap(),
    };
    open_item(&key(&v["vk"]), &ctx, &unhex(s(&v["blob"]))).map(|(_, p)| p)
}

#[test]
fn recovery_codes() {
    let doc: Value = serde_json::from_str(FILE).unwrap();
    for v in doc["recovery_codes"].as_array().unwrap() {
        let k = key(&v["key"]);
        assert_eq!(&*encode_recovery_key(&k), s(&v["code"]));
        assert_eq!(decode_recovery_key(s(&v["code"])).unwrap(), k);
    }
    for v in doc["bad_recovery_codes"].as_array().unwrap() {
        let want = match s(&v["error"]) {
            "checksum" => RecoveryError::Checksum,
            "malformed" => RecoveryError::Malformed,
            e => panic!("unknown error {e}"),
        };
        assert_eq!(decode_recovery_key(s(&v["code"])).err(), Some(want), "{v}");
    }
}

#[test]
fn wrappers_open_the_account_key() {
    let doc: Value = serde_json::from_str(FILE).unwrap();
    let list = doc["wrappers"].as_array().unwrap();
    assert!(list.len() >= 3);
    for v in list {
        let (hdr, k) = (header_of(v), v.get("key").map(key));
        let blob = unhex(s(&v["blob"]));
        let ak = unwrap_account_key(&blob, &wrapper_of(v, &hdr, &k)).unwrap();
        assert_eq!(hex(ak.expose()), s(&v["ak"]), "{}", v["kind"]);
        // alternative spellings of the same password (NFC vs NFD) open it too
        for alt in v
            .get("also_opens_with")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let mut v2 = v.clone();
            v2["password"] = alt.clone();
            let ak = unwrap_account_key(&blob, &wrapper_of(&v2, &hdr, &k)).unwrap();
            assert_eq!(hex(ak.expose()), s(&v["ak"]));
        }
        // a wrong secret must not open it
        let bad = v["wrong"].clone();
        if !bad.is_null() {
            let mut v2 = v.clone();
            v2[if v["kind"] == "master" {
                "password"
            } else {
                "key"
            }] = bad;
            let k2 = v2.get("key").map(key);
            assert!(unwrap_account_key(&blob, &wrapper_of(&v2, &hdr, &k2)).is_err());
        }
    }
}

#[test]
fn records_decrypt_to_the_expected_payload() {
    let doc: Value = serde_json::from_str(FILE).unwrap();
    let list = doc["records"].as_array().unwrap();
    assert!(list.len() >= 2);
    for v in list {
        let payload = open_record(v).unwrap();
        assert_eq!(
            serde_json::to_value(&payload).unwrap(),
            v["payload"],
            "{}",
            v["record"]
        );
    }
}

#[test]
fn bad_records_are_rejected() {
    let doc: Value = serde_json::from_str(FILE).unwrap();
    let list = doc["bad_records"].as_array().unwrap();
    assert!(list.len() >= 6);
    for v in list {
        assert!(open_record(v).is_err(), "accepted: {}", v["why"]);
    }
}

// ---- generator --------------------------------------------------------------------------

fn fixed(b: u8) -> Key {
    Key::from_bytes([b; 32])
}

#[test]
#[ignore = "rewrites the frozen vector file; run deliberately"]
fn regenerate() {
    // recovery codes: fixed keys plus a patterned one
    let keys: Vec<Key> = vec![
        fixed(0x00),
        fixed(0xff),
        Key::from_bytes(core::array::from_fn(|i| u8::try_from(i * 7 + 1).unwrap())),
    ];
    let recovery_codes: Vec<Value> = keys
        .iter()
        .map(|k| json!({"key": hex(k.expose()), "code": &*encode_recovery_key(k)}))
        .collect();
    let good = encode_recovery_key(&keys[2]).replace('-', "");
    let mut typo = good.clone().into_bytes();
    typo[10] = if typo[10] == b'0' { b'1' } else { b'0' };
    let swapped = {
        let mut t = good.clone().into_bytes();
        t.swap(3, 4);
        t
    };
    let bad_recovery_codes = json!([
        {"code": String::from_utf8(typo).unwrap(), "error": "checksum", "why": "one mistyped symbol"},
        {"code": String::from_utf8(swapped).unwrap(), "error": "checksum", "why": "adjacent swap"},
        {"code": &good[..53], "error": "malformed", "why": "too short"},
        {"code": good.replacen(&good[..1], "U", 1), "error": "malformed", "why": "U is not in the alphabet"},
    ]);

    // wrappers
    let ak = fixed(0x42);
    let salt = [0x5a; 16];
    let hdr = MasterHeader {
        salt,
        params: KdfParams::new(19 * 1024, 2, 1).unwrap(),
        pw_norm: PW_NORM,
    };
    let master = wrap_account_key(
        &ak,
        &Wrapper::Master {
            password: "caf\u{e9}",
            header: &hdr,
        },
    )
    .unwrap();
    let rec = fixed(0x07);
    let recovery = wrap_account_key(&ak, &Wrapper::Recovery(&rec)).unwrap();
    let dev = fixed(0x09);
    let device = wrap_account_key(
        &ak,
        &Wrapper::Device {
            key: &dev,
            device_id: b"device-1",
        },
    )
    .unwrap();
    let wrappers = json!([
        {"kind": "master", "password": "caf\u{e9}", "also_opens_with": ["cafe\u{301}"], "wrong": "cafe",
         "salt": hex(&salt), "m_kib": 19 * 1024, "t": 2, "p": 1, "pw_norm": PW_NORM,
         "ak": hex(ak.expose()), "blob": hex(&master)},
        {"kind": "recovery", "key": hex(rec.expose()), "wrong": hex(fixed(8).expose()),
         "ak": hex(ak.expose()), "blob": hex(&recovery)},
        {"kind": "device", "key": hex(dev.expose()), "device_id": "device-1", "wrong": hex(fixed(10).expose()),
         "ak": hex(ak.expose()), "blob": hex(&device)},
    ]);

    // records
    let vk = fixed(0x33);
    let hlc = "0000018f0a1b2c3d00010000";
    let mut a = Payload::new_login(Item {
        title: "Example \u{1f510}".into(),
        username: Some("moritz".into()),
        password: Some("p\u{e4}ss w\u{f6}rd".into()),
        urls: vec![Url {
            url: "https://example.com".into(),
            ..Url::default()
        }],
        created_at: 1_700_000_000_000,
        updated_at: 1_700_000_000_001,
        ..Item::default()
    });
    a.fields_hlc.insert("password".into(), hlc.into());
    let mut b = a.clone();
    b.data.title = "From a newer client".into();
    b.unknown
        .insert("future_top".into(), json!({"x": [1, 2, null]}));
    b.data.unknown.insert("future_field".into(), json!("kept"));
    b.extras
        .insert("source".into(), json!({"app": "bitwarden", "type": 1}));

    let mut records = Vec::new();
    for (id, tomb, key_gen, p) in [("item-1", false, 3u32, &a), ("item-2", false, 0, &b)] {
        let ctx = RecordContext {
            vault_id: b"vault-1",
            record_id: id.as_bytes(),
            hlc,
            tombstone: tomb,
        };
        let blob = seal_item(&vk, key_gen, &ctx, p).unwrap();
        records.push(json!({
            "vk": hex(vk.expose()), "key_gen": key_gen, "vault": "vault-1", "record": id,
            "hlc": hlc, "tombstone": tomb, "blob": hex(&blob),
            "payload": serde_json::to_value(p).unwrap(),
        }));
    }

    // negative records, all derived from item-1
    let base = records[0].clone();
    let with = |why: &str, f: &dyn Fn(&mut Value)| {
        let mut v = base.clone();
        f(&mut v);
        v["why"] = json!(why);
        v.as_object_mut().unwrap().remove("payload");
        v
    };
    let flip = |v: &mut Value, at: usize| {
        let mut b = unhex(s(&v["blob"]));
        b[at] ^= 1;
        v["blob"] = json!(hex(&b));
    };
    let bad_records = vec![
        with("other record id", &|v| v["record"] = json!("item-2")),
        with("other vault id", &|v| v["vault"] = json!("vault-2")),
        with("other revision", &|v| {
            v["hlc"] = json!("0000018f0a1b2c3d00010001")
        }),
        with("tombstone flag flipped", &|v| v["tombstone"] = json!(true)),
        with("wrong vault key", &|v| {
            v["vk"] = json!(hex(fixed(0x34).expose()))
        }),
        with("envelope version 0", &|v| flip(v, 0)),
        with("suite id 0", &|v| flip(v, 1)),
        with("key_gen altered", &|v| flip(v, 5)),
        with("nonce altered", &|v| flip(v, 10)),
        with("ciphertext altered", &|v| flip(v, 40)),
        with("truncated", &|v| {
            let b = unhex(s(&v["blob"]));
            v["blob"] = json!(hex(&b[..b.len() - 1]));
        }),
    ];

    let doc = json!({
        "version": 1,
        "about": "Null Seal shared test vectors; hex = lowercase. See core/crates/seal-core/tests/vectors.rs.",
        "recovery_codes": recovery_codes,
        "bad_recovery_codes": bad_recovery_codes,
        "wrappers": wrappers,
        "records": records,
        "bad_records": bad_records,
    });
    std::fs::write(PATH, serde_json::to_string_pretty(&doc).unwrap() + "\n").unwrap();
}
