//! Hybrid logical clock. A stamp is `{wall_ms:012x}{counter:04x}{node:08x}`: fixed-width
//! lowercase hex, so plain string order (what the relay and the store compare) is HLC order.
//!
//! The core has no clock of its own: callers pass wall time in milliseconds. A stamp from
//! any device that was observed is never reused or undercut, so edits stay monotonic even
//! when this device's wall clock is behind or jumps backwards.

use core_store::{Store, StoreError};

const META: &str = "sync.clock";
/// Remote stamps further ahead than this are not trusted to move our clock.
pub const MAX_DRIFT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug)]
pub enum ClockError {
    /// 65,536 stamps within one millisecond of a stuck wall time; practically unreachable.
    CounterOverflow,
    Store(StoreError),
}

impl From<StoreError> for ClockError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl core::fmt::Display for ClockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::CounterOverflow => f.write_str("clock counter overflow"),
            Self::Store(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for ClockError {}

/// Parse a stamp into `(wall_ms, counter)`; `None` unless it is exactly 24 lowercase hex chars.
pub fn parse(hlc: &str) -> Option<(u64, u16)> {
    if hlc.len() != 24
        || !hlc
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some((
        u64::from_str_radix(&hlc[..12], 16).ok()?,
        u16::from_str_radix(&hlc[12..16], 16).ok()?,
    ))
}

#[derive(Debug)]
pub struct Clock {
    last: (u64, u16),
    node: u32,
}

impl Clock {
    /// Restore from the store (or start at zero). `node` distinguishes devices in a tie.
    pub fn load(store: &Store, node: u32) -> Result<Self, ClockError> {
        let last = store
            .meta_get(META)?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| parse(&s))
            .unwrap_or((0, 0));
        Ok(Self { last, node })
    }

    fn save(&self, store: &Store) -> Result<(), ClockError> {
        store.meta_set(
            META,
            format!("{:012x}{:04x}{:08x}", self.last.0, self.last.1, self.node).as_bytes(),
        )?;
        Ok(())
    }

    /// A fresh stamp strictly greater than every stamp this clock has issued or observed.
    pub fn tick(&mut self, store: &Store, now_ms: u64) -> Result<String, ClockError> {
        let next = if now_ms > self.last.0 {
            (now_ms, 0)
        } else {
            (
                self.last.0,
                self.last
                    .1
                    .checked_add(1)
                    .ok_or(ClockError::CounterOverflow)?,
            )
        };
        self.last = next;
        self.save(store)?;
        Ok(format!("{:012x}{:04x}{:08x}", next.0, next.1, self.node))
    }

    /// Fold in a stamp seen on a record. Returns false (ignored) if it is malformed or more
    /// than [`MAX_DRIFT_MS`] ahead of `now_ms`, so a hostile relay cannot park our clock in
    /// the far future. Call [`Clock::persist`] after a batch.
    pub fn observe(&mut self, hlc: &str, now_ms: u64) -> bool {
        match parse(hlc) {
            Some(p) if p.0 <= now_ms.saturating_add(MAX_DRIFT_MS) => {
                self.last = self.last.max(p);
                true
            }
            _ => false,
        }
    }

    pub fn persist(&self, store: &Store) -> Result<(), ClockError> {
        self.save(store)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_across_skew_and_restart() {
        let store = Store::open_in_memory().unwrap();
        let mut c = Clock::load(&store, 7).unwrap();
        let a = c.tick(&store, 1_000_000).unwrap();
        let b = c.tick(&store, 1_000_000).unwrap(); // same millisecond
        let back = c.tick(&store, 500).unwrap(); // wall clock jumped backwards
        assert!(a < b && b < back, "{a} {b} {back}");
        assert!(a.ends_with("00000007"));

        // a remote device that is ahead (but plausible) pulls our clock forward
        assert!(c.observe("0000000f4a40000500000001", 1_000_000));
        let after = c.tick(&store, 1_000_000).unwrap();
        assert!(after.as_str() > "0000000f4a40000500000001");

        // restart: the stored state keeps us ahead even with a stale wall clock
        let mut c2 = Clock::load(&store, 7).unwrap();
        assert!(c2.tick(&store, 1).unwrap() > after);
    }

    #[test]
    fn rejects_far_future_and_malformed_stamps() {
        let store = Store::open_in_memory().unwrap();
        let mut c = Clock::load(&store, 1).unwrap();
        assert!(!c.observe("ffffffffffff000000000001", 1_000));
        assert!(!c.observe("not-a-stamp", 1_000));
        assert!(!c.observe("0000000F4A40000000000001", 1_000)); // uppercase is not canonical
        assert!(c.tick(&store, 1_000).unwrap().starts_with("0000000003e8"));
    }

    #[test]
    fn counter_overflow_is_an_error_not_a_wrap() {
        let store = Store::open_in_memory().unwrap();
        let mut c = Clock::load(&store, 1).unwrap();
        assert!(c.observe("0000000003e8ffff00000001", 1_000));
        assert!(matches!(
            c.tick(&store, 1_000),
            Err(ClockError::CounterOverflow)
        ));
    }
}
