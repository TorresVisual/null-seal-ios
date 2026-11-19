#![allow(clippy::unwrap_used)]

use super::*;
use core_crypto::KdfParams;
use core_keys::{MasterHeader, new_account_key, new_vault_key, wrap_account_key, wrap_vault_key};
use core_vault::{Item, Payload};

const PW: &str = "correct horse battery";

struct Fixture {
    store: Store,
    header: MasterHeader,
    ak_wrapper: Vec<u8>,
    vaults: Vec<VaultEntry>,
}

fn master<'a>(header: &'a MasterHeader, password: &'a str) -> Wrapper<'a> {
    Wrapper::Master { password, header }
}

fn fixture() -> Fixture {
    let ak = new_account_key().unwrap();
    let header = MasterHeader::new(KdfParams::new(19 * 1024, 2, 1).unwrap()).unwrap();
    let ak_wrapper = wrap_account_key(&ak, &master(&header, PW)).unwrap();
    let vk = new_vault_key().unwrap();
    let vaults = vec![VaultEntry {
        id: "v1".into(),
        key_gen: 2,
        wrapped_key: wrap_vault_key(&ak, 0, b"v1", 2, &vk).unwrap(),
        old: vec![],
    }];
    let store = Store::open_in_memory().unwrap();
    // seed the store the way an unlocked session would
    let mut s = Session::new();
    s.unlock(0, &store, &master(&header, PW), &ak_wrapper, &vaults)
        .unwrap();
    for (id, title) in [("a", "Bank"), ("b", "Mail")] {
        let item = Item {
            title: title.into(),
            password: Some("pw-secret".into()),
            ..Item::default()
        };
        let rec = s
            .seal_record(
                "v1",
                id,
                &format!("{:024x}", 1),
                false,
                &Payload::new_login(item),
            )
            .unwrap();
        store.put(&rec).unwrap();
    }
    Fixture {
        store,
        header,
        ak_wrapper,
        vaults,
    }
}

fn unlocked(f: &Fixture, now: u64) -> Session {
    let mut s = Session::new();
    s.unlock(
        now,
        &f.store,
        &master(&f.header, PW),
        &f.ak_wrapper,
        &f.vaults,
    )
    .unwrap();
    s
}

fn try_unlock(f: &Fixture, s: &mut Session, password: &str, now: u64) -> Result<(), SessionError> {
    s.unlock(
        now,
        &f.store,
        &master(&f.header, password),
        &f.ak_wrapper,
        &f.vaults,
    )
}

#[test]
fn unlock_transitions_and_reads() {
    let f = fixture();
    let mut s = Session::new();
    assert_eq!(s.state(), State::Locked);
    s.begin_unlock(0).unwrap();
    assert_eq!(s.state(), State::Unlocking);
    let w = master(&f.header, PW);
    s.finish_unlock(0, Opened::open(&f.store, &w, &f.ak_wrapper, &f.vaults))
        .unwrap();
    assert_eq!(s.state(), State::Unlocked);

    assert_eq!(s.search("v1", "bank").unwrap(), ["a"]);
    assert_eq!(s.search("v1", "").unwrap().len(), 2);
    let rec = f.store.get("a").unwrap().unwrap();
    assert_eq!(s.open_record(&rec).unwrap().data.title, "Bank");
    assert!(matches!(
        s.search("nope", ""),
        Err(SessionError::NoSuchVault)
    ));
    assert!(matches!(s.begin_unlock(1), Err(SessionError::WrongState)));
}

#[test]
fn locked_session_cannot_read_or_write_items() {
    let f = fixture();
    let rec = f.store.get("a").unwrap().unwrap();
    let p = Payload::new_login(Item::default());
    let mut s = unlocked(&f, 0);
    s.lock();
    assert_eq!(s.state(), State::Locked);
    assert!(matches!(s.search("v1", ""), Err(SessionError::Locked)));
    assert!(matches!(s.skipped("v1"), Err(SessionError::Locked)));
    assert!(matches!(s.open_record(&rec), Err(SessionError::Locked)));
    assert!(matches!(
        s.seal_record("v1", "x", "h", false, &p),
        Err(SessionError::Locked)
    ));
    assert!(matches!(
        s.refresh_index(&f.store, "v1"),
        Err(SessionError::Locked)
    ));
    // never-unlocked and mid-unlock sessions are just as closed
    let mut fresh = Session::new();
    assert!(matches!(fresh.search("v1", ""), Err(SessionError::Locked)));
    fresh.begin_unlock(0).unwrap();
    assert!(matches!(fresh.open_record(&rec), Err(SessionError::Locked)));
    s.lock(); // idempotent
}

#[test]
fn wipe_zeroizes_keys_and_drops_the_index() {
    let f = fixture();
    let w = master(&f.header, PW);
    let mut o = Opened::open(&f.store, &w, &f.ak_wrapper, &f.vaults).unwrap();
    assert_ne!(o.vaults[0].vk.expose(), &[0u8; 32]);
    assert_eq!(o.vaults[0].index.len(), 2);
    o.wipe(); // what Drop (and therefore lock) runs
    assert_eq!(o.vaults[0].vk.expose(), &[0u8; 32]);
    assert_eq!(o.vaults[0].index.len(), 0);
}

#[test]
fn lock_cancels_an_unlock_in_progress() {
    let f = fixture();
    let mut s = Session::new();
    s.begin_unlock(0).unwrap();
    let w = master(&f.header, PW);
    let opened = Opened::open(&f.store, &w, &f.ak_wrapper, &f.vaults);
    s.lock(); // e.g. the screen locked while Argon2id was running
    assert!(matches!(
        s.finish_unlock(1, opened),
        Err(SessionError::WrongState)
    ));
    assert_eq!(s.state(), State::Locked);
}

#[test]
fn idle_timeout_locks_and_touch_defers_it() {
    let f = fixture();
    let mut s = unlocked(&f, 1000);
    s.set_idle_timeout(Some(10_000));
    assert!(!s.tick(10_999));
    s.touch(8000);
    assert!(!s.tick(17_999), "touch pushes the deadline out");
    s.touch(5000); // a stale reading never moves it backwards
    assert!(!s.tick(17_999));
    assert!(s.tick(18_000));
    assert_eq!(s.state(), State::Locked);
    assert!(!s.tick(99_999), "nothing to lock");

    let mut s = unlocked(&f, 0);
    s.set_idle_timeout(None);
    assert!(!s.tick(u64::MAX));
    assert_eq!(s.state(), State::Unlocked);
}

#[test]
fn wrong_secret_fails_closed_then_backs_off_then_resets() {
    let f = fixture();
    let mut s = Session::new();
    // the first two failures cost nothing
    assert!(matches!(
        try_unlock(&f, &mut s, "nope", 0),
        Err(SessionError::Crypto)
    ));
    assert!(matches!(
        try_unlock(&f, &mut s, "nope", 0),
        Err(SessionError::Crypto)
    ));
    assert_eq!(s.state(), State::Locked);
    assert!(matches!(
        try_unlock(&f, &mut s, "nope", 0),
        Err(SessionError::Crypto)
    ));
    // third failure: 1 s delay, and even the right password is refused until it passes
    assert!(matches!(
        try_unlock(&f, &mut s, PW, 400),
        Err(SessionError::Delayed { retry_in_ms: 600 })
    ));
    assert_eq!(s.state(), State::Locked);
    try_unlock(&f, &mut s, PW, 1000).unwrap();
    // success resets the counter
    s.lock();
    assert!(matches!(
        try_unlock(&f, &mut s, "nope", 2000),
        Err(SessionError::Crypto)
    ));
    try_unlock(&f, &mut s, PW, 2000).unwrap();
}

#[test]
fn delay_schedule() {
    let d: Vec<u64> = (0..12).map(failed_attempt_delay_ms).collect();
    assert_eq!(
        d,
        [
            0, 0, 0, 1000, 2000, 4000, 8000, 16_000, 32_000, 60_000, 60_000, 60_000
        ]
    );
    assert_eq!(failed_attempt_delay_ms(u32::MAX), 60_000);
}

#[test]
fn non_crypto_failures_do_not_count_as_attempts() {
    let mut s = Session::new();
    for _ in 0..10 {
        s.begin_unlock(0).unwrap();
        let err = s.finish_unlock(0, Err(SessionError::NoSuchVault));
        assert!(matches!(err, Err(SessionError::NoSuchVault)));
    }
    s.begin_unlock(0).unwrap();
}

#[test]
fn seal_record_round_trips_through_store_and_index() {
    let f = fixture();
    let mut s = unlocked(&f, 0);
    let p = Payload::new_login(Item {
        title: "New site".into(),
        ..Item::default()
    });
    let rec = s
        .seal_record("v1", "c", &format!("{:024x}", 2), false, &p)
        .unwrap();
    assert!(f.store.put(&rec).unwrap());
    assert!(
        s.search("v1", "new site").unwrap().is_empty(),
        "index is stale until refreshed"
    );
    s.refresh_index(&f.store, "v1").unwrap();
    assert_eq!(s.search("v1", "new site").unwrap(), ["c"]);
    assert_eq!(s.open_record(&rec).unwrap(), p);
}
