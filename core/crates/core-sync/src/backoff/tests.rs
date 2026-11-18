#![allow(clippy::unwrap_used)]

use super::*;

fn fail(s: &Store, now: u64, e: SyncError) {
    record(s, now, Some(&e)).unwrap();
}

#[test]
fn failures_back_off_exponentially_and_block_attempts_until_due() {
    let s = Store::open_in_memory().unwrap();
    fail(&s, 0, SyncError::Transport("down".into()));
    assert_eq!(status(&s, 1).unwrap().unwrap().retry_at_ms, 5_000);
    // inside the pause the closure never runs
    let b = status(&s, 1_000).unwrap().unwrap(); // inside the pause
    assert!(b.failures == 1 && !b.quota);
    assert_eq!(status(&s, 5_000).unwrap(), None); // due

    fail(&s, 5_000, SyncError::Status(503));
    assert_eq!(
        status(&s, 5_001).unwrap().unwrap().retry_at_ms,
        5_000 + 10_000
    );
    for i in 0..30 {
        let now = 1_000_000 * (i + 1);
        fail(&s, now, SyncError::Transport("down".into()));
        assert!(status(&s, now).unwrap().unwrap().retry_at_ms <= now + CAP_MS);
    }
}

#[test]
fn quota_is_reported_and_waits_longer() {
    let s = Store::open_in_memory().unwrap();
    fail(&s, 0, SyncError::Status(429));
    let b = status(&s, 1).unwrap().unwrap();
    assert!(b.quota);
    assert_eq!(b.retry_at_ms, QUOTA_BASE_MS);
}

#[test]
fn success_and_permanent_errors_clear_or_skip_the_pause() {
    let s = Store::open_in_memory().unwrap();
    fail(&s, 0, SyncError::Transport("down".into()));
    record(&s, 10_000, None).unwrap();
    assert_eq!(status(&s, 10_001).unwrap(), None);
    fail(&s, 20_000, SyncError::Status(401)); // not enrolled: waiting will not fix it
    assert_eq!(status(&s, 20_001).unwrap(), None);
}

#[test]
fn a_clock_that_moved_back_does_not_lock_sync_out() {
    let s = Store::open_in_memory().unwrap();
    fail(&s, 10_000_000_000, SyncError::Transport("down".into()));
    assert_eq!(status(&s, 1).unwrap(), None);
}
