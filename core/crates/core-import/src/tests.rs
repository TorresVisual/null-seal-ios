#![allow(clippy::unwrap_used)]

use super::*;
use core_vault::ItemType;

const UNENCRYPTED: &str = include_str!("../../../tests/fixtures/bitwarden/unencrypted.json");
const ORG: &str = include_str!("../../../tests/fixtures/bitwarden/org-collections.json");
const PASSWORD_PROTECTED: &str =
    include_str!("../../../tests/fixtures/bitwarden/password-protected.json");
const GOLDEN_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/fixtures/bitwarden/golden"
);

/// Compare against a reviewed golden file; `UPDATE_GOLDEN=1 cargo test -p core-import` rewrites it.
fn golden(name: &str, got: &Import) {
    let path = format!("{GOLDEN_DIR}/{name}");
    let json = serde_json::to_string_pretty(got).unwrap() + "\n";
    if std::env::var_os("UPDATE_GOLDEN").is_some() {
        std::fs::create_dir_all(GOLDEN_DIR).unwrap();
        std::fs::write(&path, &json).unwrap();
    }
    let want = std::fs::read_to_string(&path)
        .unwrap()
        .replace("\r\n", "\n");
    assert_eq!(
        json, want,
        "golden {name} differs; review, then UPDATE_GOLDEN=1"
    );
}

fn run(src: &str) -> Import {
    bitwarden_json(src.as_bytes()).unwrap()
}

fn by_id<'a>(i: &'a Import, id: &str) -> &'a Payload {
    &i.items.iter().find(|x| x.source_id == id).unwrap().payload
}

#[test]
fn golden_individual_export() {
    golden("unencrypted.import.json", &run(UNENCRYPTED));
}

#[test]
fn golden_organization_export() {
    golden("org-collections.import.json", &run(ORG));
}

#[test]
fn every_item_is_imported_or_reported_skipped() {
    let src: Value = serde_json::from_str(UNENCRYPTED).unwrap();
    let total = src["items"].as_array().unwrap().len();
    let i = run(UNENCRYPTED);
    let skipped: HashSet<_> = i
        .report
        .iter()
        .filter(|f| f.outcome == Outcome::Skipped)
        .map(|f| f.id.as_str())
        .collect();
    assert_eq!(i.items.len() + skipped.len(), total);
    // Only the unknown type 99 is skipped; 3..=8 import as notes.
    assert_eq!(skipped.len(), 1);
}

#[test]
fn structured_types_import_as_notes_with_the_object_kept() {
    let i = run(UNENCRYPTED);
    for (id, key) in [
        ("30000000-0000-4000-8000-000000000001", "card"),
        ("40000000-0000-4000-8000-000000000001", "identity"),
        ("50000000-0000-4000-8000-000000000001", "sshKey"),
        ("60000000-0000-4000-8000-000000000001", "bankAccount"),
        ("70000000-0000-4000-8000-000000000001", "driversLicense"),
        ("80000000-0000-4000-8000-000000000001", "passport"),
    ] {
        let p = by_id(&i, id);
        assert_eq!(p.item_type, ItemType::Note, "{key}");
        assert!(p.extras["bitwarden"][key].is_object(), "{key}");
        assert!(p.extras["bitwarden"]["type"].is_u64(), "{key}");
        assert!(i.report.iter().any(|f| f.id == id && f.path == key));
    }
}

const CSV: &str = include_str!("../../../tests/fixtures/bitwarden/unencrypted.csv");

#[test]
fn golden_csv_export() {
    golden(
        "unencrypted-csv.import.json",
        &bitwarden_csv(CSV.as_bytes()).unwrap(),
    );
}

#[test]
fn csv_maps_logins_and_notes() {
    let i = bitwarden_csv(CSV.as_bytes()).unwrap();
    assert_eq!(i.items.len(), 3);
    let d = &i.items[0].payload.data;
    assert_eq!(d.folder.as_deref(), Some("Personal"));
    assert!(d.favorite && d.reprompt);
    assert_eq!(
        d.notes.as_deref(),
        Some("Synthetic login.\nSecond line of notes.")
    );
    assert_eq!(d.urls.len(), 2);
    assert_eq!(d.urls[1].url, "https://example.com:8443");
    assert!(d.totp.as_deref().unwrap().starts_with("otpauth://totp/"));
    // The hidden-field text has no home yet: kept verbatim and reported.
    let kept = i.items[0].payload.extras["bitwarden"]["fields"]
        .as_str()
        .unwrap();
    assert!(kept.contains("api token"));
    assert!(
        i.report
            .iter()
            .any(|f| f.path == "fields" && f.outcome == Outcome::Preserved)
    );
    assert_eq!(i.items[2].payload.item_type, ItemType::Note);
    // Same file, same ids: re-import is idempotent.
    let again = bitwarden_csv(CSV.as_bytes()).unwrap();
    assert_eq!(i.items[0].source_id, again.items[0].source_id);
}

#[test]
fn csv_report_never_holds_values() {
    let report = serde_json::to_string(&bitwarden_csv(CSV.as_bytes()).unwrap().report).unwrap();
    for secret in ["synthetic-password", "JBSWY3DP", "synthetic-hidden"] {
        assert!(!report.contains(secret), "{secret} leaked into the report");
    }
}

#[test]
fn csv_quirks_are_reported_not_lost() {
    // BOM, CRLF, reordered columns, an unknown column, a card row, a short row, a duplicate.
    let src = "\u{feff}name,type,extra\r\nA,login,keep\r\nB,card,\r\nshort\r\nA,login,keep\r\n";
    let i = bitwarden_csv(src.as_bytes()).unwrap();
    assert_eq!(i.items.len(), 1);
    assert_eq!(i.items[0].payload.extras["bitwarden"]["extra"], "keep");
    let paths: Vec<_> = i.report.iter().map(|f| f.path.as_str()).collect();
    assert_eq!(paths, ["extra", "type=card", "row[3]", "row (duplicate)"]);
}

#[test]
fn csv_rejects_what_it_cannot_read() {
    for bad in ["", "a,b\n1,2\n", "name,type\n\"open,login\n"] {
        assert_eq!(
            bitwarden_csv(bad.as_bytes()).unwrap_err(),
            ImportError::Format
        );
    }
    assert_eq!(
        bitwarden_csv(&[0xff, 0xfe]).unwrap_err(),
        ImportError::Format
    );
}

#[test]
fn nothing_is_lost_from_a_mapped_item() {
    let i = run(UNENCRYPTED);
    let p = by_id(&i, "10000000-0000-4000-8000-000000000001");
    let d = &p.data;
    assert_eq!(d.title, "Example Mail");
    assert_eq!(d.folder.as_deref(), Some("Personal"));
    assert!(d.favorite && d.reprompt);
    assert_eq!(d.username.as_deref(), Some("synthetic.user@example.com"));
    assert!(d.totp.as_deref().unwrap().starts_with("otpauth://totp/"));
    // null is "use the default", distinct from "domain" (0).
    let modes: Vec<_> = d.urls.iter().map(|u| u.r#match.as_deref()).collect();
    assert_eq!(
        modes,
        [
            None,
            Some("host"),
            Some("exact"),
            Some("regex"),
            Some("never"),
            Some("starts_with")
        ]
    );
    assert_eq!(d.created_at, 1_732_090_500_000);
    assert_eq!(d.updated_at, 1_772_359_200_000);
    let bw = &p.extras["bitwarden"];
    assert_eq!(bw["fields"].as_array().unwrap().len(), 4);
    assert_eq!(bw["passwordHistory"].as_array().unwrap().len(), 2);
}

#[test]
fn passkeys_trash_and_odd_totp_are_preserved() {
    let i = run(UNENCRYPTED);
    let pk = by_id(&i, "10000000-0000-4000-8000-000000000004");
    assert_eq!(
        pk.extras["bitwarden"]["login.fido2Credentials"][0]["rpId"],
        "passkey.example.com"
    );
    let trashed = by_id(&i, "10000000-0000-4000-8000-000000000005");
    assert!(trashed.data.deleted_at.is_some());
    assert!(trashed.extras["bitwarden"]["archivedDate"].is_string());
    let steam = by_id(&i, "10000000-0000-4000-8000-000000000003");
    assert_eq!(steam.data.totp.as_deref(), Some("steam://ABCDEFGHIJKLMNOP"));
}

#[test]
fn unicode_and_whitespace_survive() {
    let i = run(UNENCRYPTED);
    let d = &by_id(&i, "10000000-0000-4000-8000-000000000006").data;
    assert_eq!(
        d.notes.as_deref(),
        Some("Multi-line\r\nnotes with CRLF and a trailing space ")
    );
    assert_eq!(d.password.as_deref(), Some("pässwörd 🔑 with spaces  "));
}

#[test]
fn notes_are_notes_and_collections_become_tags() {
    let i = run(UNENCRYPTED);
    assert_eq!(
        by_id(&i, "20000000-0000-4000-8000-000000000001").item_type,
        ItemType::Note
    );
    let org = run(ORG);
    let p = by_id(&org, "a0000000-0000-4000-8000-000000000001");
    assert_eq!(p.data.tags, ["collection:Shared/Team", "collection:Ops"]);
    assert!(p.extras["bitwarden"]["organizationId"].is_string());
}

#[test]
fn report_never_holds_values() {
    let report = serde_json::to_string(&run(UNENCRYPTED).report).unwrap();
    for secret in ["synthetic-password", "JBSWY3DP", "synthetic-hidden", "4111"] {
        assert!(!report.contains(secret), "{secret} leaked into the report");
    }
}

#[test]
fn duplicate_ids_in_one_export_are_reported() {
    let item = json!({"id":"x","type":2,"name":"n"});
    let src = json!({"encrypted":false,"items":[item,item]}).to_string();
    let i = run(&src);
    assert_eq!(i.items.len(), 1);
    assert_eq!(i.report[0].path, "id (duplicate)");
}

#[test]
fn unreadable_values_are_preserved_not_dropped() {
    let src = json!({"items":[{"id":"x","type":1,"name":"n","favorite":"yes",
        "login":{"password":42,"uris":[{"uri":"https://a.test","match":9,"uriChecksum":"c"}]}}]})
    .to_string();
    let i = run(&src);
    let p = by_id(&i, "x");
    assert_eq!(p.extras["bitwarden"]["favorite"], "yes");
    assert_eq!(p.extras["bitwarden"]["login.password"], 42);
    assert_eq!(p.data.urls[0].unknown["match"], 9);
    assert_eq!(p.data.urls[0].unknown["uriChecksum"], "c");
}

#[test]
fn rejects_what_it_cannot_read() {
    assert_eq!(
        bitwarden_json(PASSWORD_PROTECTED.as_bytes()).unwrap_err(),
        ImportError::PasswordProtected
    );
    let account_key = json!({"encrypted":true,"items":[]}).to_string();
    assert_eq!(
        bitwarden_json(account_key.as_bytes()).unwrap_err(),
        ImportError::Encrypted
    );
    for bad in [
        "",
        "[]",
        "{}",
        r#"{"items":{}}"#,
        r#"{"encrypted":1,"items":[]}"#,
    ] {
        assert_eq!(
            bitwarden_json(bad.as_bytes()).unwrap_err(),
            ImportError::Format
        );
    }
}

#[test]
fn timestamps() {
    assert_eq!(parse_ms("1970-01-01T00:00:00.000Z"), Some(0));
    assert_eq!(parse_ms("2026-03-01T10:00:00Z"), Some(1_772_359_200_000));
    assert_eq!(parse_ms("2026-03-01T10:00:00.5Z"), Some(1_772_359_200_500));
    assert_eq!(
        parse_ms("2024-02-29T23:59:59.999Z"),
        Some(1_709_251_199_999)
    );
    for bad in [
        "",
        "2026-03-01",
        "2026-13-01T00:00:00.000Z",
        "2026-03-01T00:00:00.000",
        "+026-03-01T00:00:00.000Z",
        "1969-12-31T23:59:59.000Z",
    ] {
        assert_eq!(parse_ms(bad), None, "{bad}");
    }
}

#[test]
fn unused_and_duplicate_folders_are_reported() {
    let src =
        json!({"folders":[{"id":"f1","name":"A"},{"id":"f2","name":"B"},{"id":"f1","name":"C"}],
        "collections":[{"id":"c1","name":"Empty"}],
        "items":[{"id":"x","type":2,"name":5,"folderId":"f1"}]})
        .to_string();
    let i = run(&src);
    let paths: Vec<_> = i.report.iter().map(|f| f.path.as_str()).collect();
    assert!(paths.contains(&"folders[2] (duplicate id)"));
    assert!(paths.contains(&"folders[f2] (unused)"));
    assert!(paths.contains(&"collections[c1] (unused)"));
    // A non-string name is kept, not turned into an empty title.
    assert_eq!(by_id(&i, "x").extras["bitwarden"]["name"], 5);
}

#[test]
fn oversize_input_is_refused() {
    let big = vec![b' '; MAX_INPUT + 1];
    assert_eq!(bitwarden_json(&big).unwrap_err(), ImportError::Format);
}

const EXPORT_PASSWORD: &str = "synthetic-export-password";

fn json_of(i: &Import) -> String {
    serde_json::to_string(i).unwrap()
}

#[test]
fn password_protected_import_equals_plaintext_import() {
    let got = bitwarden_json_password(PASSWORD_PROTECTED.as_bytes(), EXPORT_PASSWORD).unwrap();
    assert_eq!(json_of(&got), json_of(&run(UNENCRYPTED)));
}

#[test]
fn wrong_password_fails_cleanly() {
    for pw in ["", "synthetic-export-passwor", "Synthetic-export-password"] {
        assert_eq!(
            bitwarden_json_password(PASSWORD_PROTECTED.as_bytes(), pw).unwrap_err(),
            ImportError::WrongPassword,
            "{pw:?}"
        );
    }
}

#[test]
fn password_protected_envelope_is_validated() {
    let ok: Value = serde_json::from_str(PASSWORD_PROTECTED).unwrap();
    let with = |k: &str, v: Value| {
        let mut e = ok.clone();
        e[k] = v;
        e.to_string()
    };
    let mut bad = vec![
        "".to_owned(),
        "[]".to_owned(),
        UNENCRYPTED.to_owned(),
        with("passwordProtected", json!(false)),
        with("kdfType", json!(2)),
        with("kdfIterations", json!(0)),
        // Over the PBKDF2 ceiling: refused before any work is done.
        with("kdfIterations", json!(u32::MAX)),
        with("salt", Value::Null),
        with("data", json!("2.AAAA")),
        with("data", json!("1.AAAA|AAAA|AAAA")),
        with("encKeyValidation_DO_NOT_EDIT", json!("not an encstring")),
    ];
    // Argon2id without its memory/parallelism, or beyond the cost ceiling.
    bad.push(with("kdfType", json!(1)));
    let mut a = ok.clone();
    (a["kdfType"], a["kdfMemory"], a["kdfParallelism"]) = (json!(1), json!(4_000_000), json!(4));
    bad.push(a.to_string());
    for b in bad {
        let e = bitwarden_json_password(b.as_bytes(), EXPORT_PASSWORD).unwrap_err();
        assert_eq!(e, ImportError::Format, "{}", &b[..b.len().min(60)]);
    }
}

#[test]
fn tampered_data_is_refused_not_imported() {
    let mut e: Value = serde_json::from_str(PASSWORD_PROTECTED).unwrap();
    let data = e["data"].as_str().unwrap().to_owned();
    // Flip one ciphertext character: the MAC no longer matches.
    let at = data.find('|').unwrap() + 1;
    let flipped = if &data[at..=at] == "A" { "B" } else { "A" };
    e["data"] = json!(format!("{}{flipped}{}", &data[..at], &data[at + 1..]));
    assert_eq!(
        bitwarden_json_password(e.to_string().as_bytes(), EXPORT_PASSWORD).unwrap_err(),
        ImportError::Format
    );
}

/// Seal `plain` as EncString type 2 the way Bitwarden does (test-only; the importer never encrypts).
fn seal(enc: &core_crypto::Key, mac: &core_crypto::Key, plain: &[u8]) -> String {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    let iv = [9u8; 16];
    let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc.expose(), &iv)
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(plain);
    let tag = core_crypto::hmac(
        core_crypto::HmacAlg::Sha256,
        mac.expose(),
        &[&iv[..], &ct].concat(),
    )
    .unwrap();
    let b = |x: &[u8]| base64::Engine::encode(&base64::engine::general_purpose::STANDARD, x);
    format!("2.{}|{}|{}", b(&iv), b(&ct), b(&tag))
}

#[test]
fn argon2id_password_protected_export_imports() {
    let (salt, pw) = ("c3ludGhldGljLWFyZ29uLXNhbHQ=", "argon pässword");
    // Bitwarden: Argon2id over the SHA-256 of the salt string; memory is in MiB in the file.
    let p = core_crypto::KdfParams::new(19 * 1024, 2, 1).unwrap();
    let master =
        core_crypto::argon2id(pw.as_bytes(), &core_crypto::sha256(salt.as_bytes()), p).unwrap();
    let enc = core_crypto::interop::hkdf_expand(&master, b"enc").unwrap();
    let mac = core_crypto::interop::hkdf_expand(&master, b"mac").unwrap();
    let env = json!({"encrypted":true,"passwordProtected":true,"salt":salt,"kdfType":1,
        "kdfIterations":2,"kdfMemory":19,"kdfParallelism":1,
        "encKeyValidation_DO_NOT_EDIT": seal(&enc, &mac, b"validation"),
        "data": seal(&enc, &mac, UNENCRYPTED.as_bytes())})
    .to_string();
    let got = bitwarden_json_password(env.as_bytes(), pw).unwrap();
    assert_eq!(json_of(&got), json_of(&run(UNENCRYPTED)));
    assert_eq!(
        bitwarden_json_password(env.as_bytes(), "other").unwrap_err(),
        ImportError::WrongPassword
    );
}
