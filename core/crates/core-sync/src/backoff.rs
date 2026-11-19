//! Retry pacing for flaky networks and free-tier limits (#43). The outbox (pending edits) and the
//! pull cursor already persist in the store, so a failed sync loses nothing; this module only
//! decides when the next attempt is allowed, and says why, so callers (timers, buttons) do not
//! hammer a relay that is down or out of quota.
//!
//! State is two numbers in the store's meta table: consecutive failures and the earliest next
//! attempt (Unix ms). The core has no timers, so callers poll [`status`] / retry on their own.
//!
//! ponytail: no jitter (one user, a handful of devices); add if many clients ever share a relay.

use crate::SyncError;
use core_store::Store;

const KEY: &str = "sync.backoff";
const BASE_MS: u64 = 5_000;
const CAP_MS: u64 = 5 * 60_000;
/// Quota limits reset on the scale of hours, so back off further before asking again.
const QUOTA_BASE_MS: u64 = 60_000;
const QUOTA_CAP_MS: u64 = 60 * 60_000;

/// Why attempts are paused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Backoff {
    /// Earliest time (Unix ms) a sync is attempted again.
    pub retry_at_ms: u64,
    /// Consecutive failed syncs.
    pub failures: u32,
    /// The relay said it is throttling or out of quota (HTTP 429), not just unreachable.
    pub quota: bool,
}

impl Backoff {
    fn delay_ms(failures: u32, quota: bool) -> u64 {
        let (base, cap) = if quota {
            (QUOTA_BASE_MS, QUOTA_CAP_MS)
        } else {
            (BASE_MS, CAP_MS)
        };
        base.saturating_mul(1 << failures.saturating_sub(1).min(20))
            .min(cap)
    }

    fn cap_ms(&self) -> u64 {
        if self.quota { QUOTA_CAP_MS } else { CAP_MS }
    }

    fn load(store: &Store) -> Result<Option<Self>, SyncError> {
        let Some(raw) = store.meta_get(KEY)? else {
            return Ok(None);
        };
        let s = String::from_utf8_lossy(&raw);
        let mut it = s.split(',').map(|p| p.parse::<u64>().ok());
        Ok(
            match (it.next().flatten(), it.next().flatten(), it.next()) {
                (Some(at), Some(n), Some(q)) => Some(Self {
                    retry_at_ms: at,
                    failures: u32::try_from(n).unwrap_or(u32::MAX),
                    quota: q == Some(1),
                }),
                _ => None, // unreadable state is no state: never lock sync out on garbage
            },
        )
    }
}

/// The pause in force at `now_ms`, if any.
pub fn status(store: &Store, now_ms: u64) -> Result<Option<Backoff>, SyncError> {
    Ok(Backoff::load(store)?
        // a retry time far beyond the cap means the clock moved back: do not stay locked out
        .filter(|b| b.retry_at_ms > now_ms && b.retry_at_ms - now_ms <= b.cap_ms()))
}

/// Forget the pause (a user-requested "sync now").
pub fn reset(store: &Store) -> Result<(), SyncError> {
    store.meta_set(KEY, b"")?;
    Ok(())
}

/// Failures that may heal by waiting; anything else (401, 413, protocol errors) is not retried
/// on a timer.
fn transient(e: &SyncError) -> Option<bool> {
    match e {
        SyncError::Transport(_) | SyncError::Unsettled => Some(false),
        SyncError::Status(429) => Some(true),
        SyncError::Status(s) if *s >= 500 => Some(false),
        _ => None,
    }
}

/// Note how a sync attempt ended: `None` (success) clears the pause, a transient failure
/// extends it. Callers check [`status`] first and skip the attempt while a pause is in force.
pub fn record(store: &Store, now_ms: u64, failure: Option<&SyncError>) -> Result<(), SyncError> {
    let Some(e) = failure else {
        return reset(store);
    };
    let Some(quota) = transient(e) else {
        return Ok(());
    };
    let failures = Backoff::load(store)?
        .map_or(0, |b| b.failures)
        .saturating_add(1);
    let at = now_ms.saturating_add(Backoff::delay_ms(failures, quota));
    store.meta_set(
        KEY,
        format!("{at},{failures},{}", u8::from(quota)).as_bytes(),
    )?;
    Ok(())
}

#[cfg(test)]
mod tests;
