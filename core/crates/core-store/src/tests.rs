#![allow(clippy::unwrap_used)]

use super::*;
use core_crypto::Key;
use core_vault::{Item, Payload, RecordContext, Url, seal_item};
use std::time::Instant;

const VAULT: &str = "vault-1";

fn vk() -> Key {
    Key::from_bytes([7; 32])
}

fn hlc(n: u64) -> String {
    format!("{n:024x}")
}

fn rec(id: &str, n: u64, tombstone: bool, item: Item) -> Record {
    let h = hlc(n);
    let ctx = RecordContext {
        vault_id: VAULT.as_bytes(),
        record_id: id.as_bytes(),
        hlc: &h,
        tombstone,
    };
    Record {
        id: id.into(),
        vault: VAULT.into(),
        blob: seal_item(&vk(), 0, &ctx, &Payload::new_login(item)).unwrap(),
        hlc: h,
        tombstone,
    }
}

fn login(title: &str, user: &str, url: &str) -> Item {
    Item {
        title: title.into(),
        username: Some(user.into()),
        password: Some("pw-canary-9f3a".into()),
        notes: Some("notes-canary-77c1".into()),
        urls: vec![Url {
            url: url.into(),
            ..Url::default()
        }],
        ..Item::default()
    }
}

fn version(s: &Store) -> usize {
    user_version(&s.conn).unwrap()
}

#[test]
fn database_file_contains_no_plaintext() {
    let path = std::env::temp_dir().join(format!("null-seal-store-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    {
        let s = Store::open(&path).unwrap();
        for i in 0..20 {
            let it = login(
                "Title-canary-5d2e",
                "user-canary-b801",
                "https://url-canary.test",
            );
            s.put(&rec(&format!("r{i}"), i + 1, false, it)).unwrap();
        }
    }
    let bytes = std::fs::read(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let has = |needle: &str| bytes.windows(needle.len()).any(|w| w == needle.as_bytes());
    assert!(has("records"), "sanity: schema text is on disk");
    for canary in [
        "Title-canary",
        "user-canary",
        "url-canary",
        "pw-canary",
        "notes-canary",
        "canary",
    ] {
        assert!(!has(canary), "{canary} found in database file");
    }
}

#[test]
fn put_is_last_writer_wins_by_hlc() {
    let s = Store::open_in_memory().unwrap();
    let (a, b) = (
        rec("x", 5, false, login("a", "u", "h")),
        rec("x", 9, false, login("b", "u", "h")),
    );
    assert!(s.put(&a).unwrap());
    assert!(s.put(&b).unwrap());
    assert!(!s.put(&a).unwrap(), "older hlc must not overwrite");
    assert!(!s.put(&b).unwrap(), "same hlc is not newer");
    assert_eq!(s.get("x").unwrap().unwrap(), b);
    assert_eq!(s.get("nope").unwrap(), None);
    assert_eq!(s.list(VAULT).unwrap(), vec![b]);
    assert!(s.list("other").unwrap().is_empty());
}

#[test]
fn search_matches_visible_fields_only() {
    let s = Store::open_in_memory().unwrap();
    let mut tagged = login("Bank", "alice", "https://bank.example");
    tagged.tags = vec!["finance".into()];
    s.put(&rec("a", 1, false, tagged)).unwrap();
    s.put(&rec(
        "b",
        2,
        false,
        login("Mail", "Bob", "https://mail.example"),
    ))
    .unwrap();
    s.put(&rec("gone", 3, true, login("Bank old", "x", "y")))
        .unwrap();
    let mut trashed = login("Bank trash", "x", "y");
    trashed.deleted_at = Some(1);
    s.put(&rec("trash", 4, false, trashed)).unwrap();

    let idx = Index::build(&s, VAULT, &[(0, &vk())]).unwrap();
    assert_eq!((idx.len(), idx.skipped.len()), (2, 0));
    assert_eq!(idx.search("BANK"), ["a"]);
    assert_eq!(idx.search("bob mail"), ["b"]);
    assert_eq!(idx.search("example finance"), ["a"]);
    assert_eq!(idx.search("example").len(), 2);
    assert_eq!(idx.search("").len(), 2);
    assert!(
        idx.search("pw-canary").is_empty(),
        "passwords are not indexed"
    );
    assert!(
        idx.search("notes-canary").is_empty(),
        "notes are not indexed"
    );
    assert!(idx.search("bank mail").is_empty());
}

#[test]
fn undecryptable_records_are_reported_not_fatal() {
    let s = Store::open_in_memory().unwrap();
    s.put(&rec("ok", 1, false, login("fine", "u", "h")))
        .unwrap();
    let mut bad = rec("bad", 2, false, login("x", "u", "h"));
    bad.blob[40] ^= 1;
    s.put(&bad).unwrap();
    // a record moved to another id fails its bound context too
    let mut moved = rec("orig", 3, false, login("x", "u", "h"));
    moved.id = "moved".into();
    s.put(&moved).unwrap();

    let idx = Index::build(&s, VAULT, &[(0, &vk())]).unwrap();
    assert_eq!(idx.search(""), ["ok"]);
    assert_eq!(idx.skipped, ["bad", "moved"]);
    // wrong key: nothing indexed, everything reported
    let idx = Index::build(&s, VAULT, &[(0, &Key::from_bytes([1; 32]))]).unwrap();
    assert!(idx.is_empty());
    assert_eq!(idx.skipped.len(), 3);
}

#[test]
fn search_over_5k_items_is_fast() {
    let s = Store::open_in_memory().unwrap();
    for i in 0..5000u64 {
        let it = login(
            &format!("Site number {i}"),
            &format!("user{i}@example.com"),
            &format!("https://site{i}.example.org/login"),
        );
        s.put(&rec(&format!("r{i}"), i + 1, false, it)).unwrap();
    }
    let idx = Index::build(&s, VAULT, &[(0, &vk())]).unwrap();
    assert_eq!(idx.len(), 5000);
    let t = Instant::now();
    for q in ["site4999", "number 77", "zzz-no-match", "EXAMPLE.org login"] {
        let _ = idx.search(q);
    }
    let per_query = t.elapsed() / 4;
    assert_eq!(idx.search("site4999"), ["r4999"]);
    assert!(per_query.as_millis() < 50, "search took {per_query:?}");
}

#[test]
fn fresh_database_is_at_latest_version_and_reopens() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(version(&s), MIGRATIONS.len());
}

#[test]
fn migrates_forward_from_the_v1_fixture() {
    let path = std::env::temp_dir().join(format!("null-seal-mig-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Connection::open(&path)
        .unwrap()
        .execute_batch(include_str!("../../../tests/fixtures/store/v1.sql"))
        .unwrap();

    let s = Store::open(&path).unwrap();
    assert_eq!(version(&s), MIGRATIONS.len());
    let r = s.get("rec-1").unwrap().unwrap();
    assert_eq!(
        (r.vault.as_str(), r.hlc.as_str(), r.blob.as_slice()),
        ("vault-1", "000000000001000000000001", &[1, 2, 3, 4, 5][..])
    );
    let idx: String = s
        .conn
        .query_row(
            "SELECT name FROM sqlite_master WHERE type='index' AND name='records_by_vault'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(idx, "records_by_vault");
    drop(s);
    // reopening an up-to-date database is a no-op
    assert_eq!(version(&Store::open(&path).unwrap()), MIGRATIONS.len());
    let _ = std::fs::remove_file(&path);
}

#[test]
fn refuses_a_database_from_a_newer_build() {
    let path = std::env::temp_dir().join(format!("null-seal-new-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    Connection::open(&path)
        .unwrap()
        .execute_batch(&format!("PRAGMA user_version = {}", MIGRATIONS.len() + 1))
        .unwrap();
    assert!(matches!(
        Store::open(&path),
        Err(StoreError::SchemaTooNew(_))
    ));
    let _ = std::fs::remove_file(&path);
}

fn plain(id: &str, n: u64) -> Record {
    Record {
        id: id.into(),
        vault: VAULT.into(),
        hlc: hlc(n),
        tombstone: false,
        blob: vec![n as u8; 4],
    }
}

#[test]
fn pending_queue_tracks_base_and_acks() {
    let s = Store::open_in_memory().unwrap();
    assert!(s.put_local(&plain("a", 1)).unwrap());
    assert!(s.put_local(&plain("a", 2)).unwrap()); // second edit keeps the first base (None)
    let p = s.pending().unwrap();
    assert_eq!(p.len(), 1);
    assert_eq!((p[0].0.hlc.clone(), p[0].1.clone()), (hlc(2), None));

    // pushed hlc 1 only; the record was edited since, so it stays queued on a new base
    s.ack("a", &hlc(1)).unwrap();
    assert_eq!(s.pending().unwrap()[0].1, Some(hlc(1)));
    s.ack("a", &hlc(2)).unwrap();
    assert!(s.pending().unwrap().is_empty());

    // a later edit of a synced record is based on the stored hlc
    s.put_local(&plain("a", 3)).unwrap();
    assert_eq!(s.pending().unwrap()[0].1, Some(hlc(2)));
    // a stale local write is refused and not queued
    assert!(!s.put_local(&plain("a", 1)).unwrap());
    assert_eq!(s.pending().unwrap().len(), 1);
}

#[test]
fn remote_newer_record_drops_local_edit_but_older_does_not() {
    let s = Store::open_in_memory().unwrap();
    s.put_local(&plain("a", 5)).unwrap();
    assert!(!s.put_remote(&plain("a", 4)).unwrap());
    assert_eq!(s.pending().unwrap().len(), 1);
    assert!(!s.put_remote(&plain("a", 5)).unwrap()); // our own echo
    assert_eq!(s.pending().unwrap().len(), 1);
    assert!(s.put_remote(&plain("a", 6)).unwrap());
    assert!(s.pending().unwrap().is_empty());
    assert_eq!(s.get("a").unwrap().unwrap().hlc, hlc(6));
}

#[test]
fn meta_round_trips_and_overwrites() {
    let s = Store::open_in_memory().unwrap();
    assert_eq!(s.meta_get("k").unwrap(), None);
    s.meta_set("k", b"one").unwrap();
    s.meta_set("k", b"two").unwrap();
    assert_eq!(s.meta_get("k").unwrap().unwrap(), b"two");
}

#[test]
fn merged_and_replaced_records_set_the_push_base_and_the_queue() {
    let s = Store::open_in_memory().unwrap();
    s.put_local(&plain("a", 5)).unwrap();
    assert!(s.is_pending("a").unwrap());
    // merge result on top of the relay copy 7: stored even though hlc 8 > 5 and queued against 7
    s.put_merged(&plain("a", 8), &hlc(7)).unwrap();
    assert_eq!(s.pending().unwrap()[0].1, Some(hlc(7)));
    // the relay copy turns out to hold everything: adopt it even though it is older than ours
    s.replace(&plain("a", 6)).unwrap();
    assert_eq!(s.get("a").unwrap().unwrap().hlc, hlc(6));
    assert!(!s.is_pending("a").unwrap());
}
