//! Push/pull loop. Pull first (so remote edits that beat ours drop our stale ones), then
//! push what is still pending; a conflict means the relay moved on, so loop again.

use crate::{Clock, Device, SyncError, Transport, b64, hlc, unb64};

/// What to do with a pulled record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Authentic: it may replace local state.
    Accept,
    /// Forged, malformed or unreadable by us: drop it.
    Reject,
    /// Possibly authentic but sealed under a key we do not hold yet (a key rotation we have not
    /// received). Stop without moving the cursor, so it is pulled again once we have the key.
    Defer,
}

/// Decides whether a pulled record is authentic (its AEAD, bound to id/vault/hlc/tombstone,
/// opens) before it may replace local state (SR-5, SR-9).
pub type Verify<'a> = &'a dyn Fn(&Record) -> Verdict;
use core_store::{Record, Store};
use serde::Deserialize;

/// What to do when a pulled record meets an unpushed local edit of the same record.
pub enum Resolution {
    /// The local copy already holds everything: keep it and push it on top of the remote one.
    Keep,
    /// The remote copy holds everything: adopt it and drop the local edit.
    Take,
    /// A merged record sealed under the fresh hlc passed to the callback: store and push it.
    Write(Record),
}

/// Decides a conflict: `(local, remote, fresh_hlc)`. The sync crate cannot read records, so the
/// caller, which holds the keys, merges them (see `core_vault::merge`).
pub type Merge<'a> = &'a dyn Fn(&Record, &Record, &str) -> Result<Resolution, SyncError>;

/// Whole-record last-writer-wins, for callers that cannot read records.
pub fn lww(local: &Record, remote: &Record, _fresh: &str) -> Result<Resolution, SyncError> {
    Ok(if remote.hlc > local.hlc {
        Resolution::Take
    } else {
        Resolution::Keep
    })
}

const PUSH_BATCH: usize = 50;
const PULL_LIMIT: usize = 100;
const MAX_ROUNDS: usize = 4;
/// Envelope overhead is small; anything bigger than this is not a record we wrote (SR-23).
const MAX_BLOB_BYTES: usize = 80 * 1024;
/// Upper bound on pages per pull, so a relay that never says "no more" cannot pin the caller.
const MAX_PAGES: usize = 500;
const MAX_ID_LEN: usize = 80;
const CURSOR: &str = "sync.cursor";

#[derive(Debug, Default, PartialEq, Eq)]
pub struct SyncReport {
    pub pushed: usize,
    pub pulled: usize,
    /// Pulled records that replaced local state.
    pub applied: usize,
    /// Push attempts the relay answered with a conflict (resolved by a later round).
    pub conflicts: usize,
    /// Pulled records merged with an unpushed local edit into a new record.
    pub merged: usize,
    /// Pulled records dropped for being malformed, implausible or failing authentication.
    pub rejected: usize,
}

impl core::ops::AddAssign for SyncReport {
    fn add_assign(&mut self, o: Self) {
        self.pushed += o.pushed;
        self.pulled += o.pulled;
        self.applied += o.applied;
        self.conflicts += o.conflicts;
        self.merged += o.merged;
        self.rejected += o.rejected;
    }
}

#[derive(Deserialize)]
struct WireRecord {
    id: String,
    vault: String,
    hlc: String,
    tomb: bool,
    blob: String,
}

#[derive(Deserialize)]
struct PullResp {
    records: Vec<WireRecord>,
    cursor: u64,
    more: bool,
}

#[derive(Deserialize)]
struct PushResp {
    accepted: Vec<String>,
    conflicts: Vec<Conflict>,
}

#[derive(Deserialize)]
struct Conflict {
    id: String,
    current: Option<WireRecord>,
}

pub(crate) fn call(
    t: &dyn Transport,
    device: &Device,
    now_ms: u64,
    method: &'static str,
    path: &str,
    body: Vec<u8>,
) -> Result<Vec<u8>, SyncError> {
    let res = t.send(&device.sign_request(method, path, body, now_ms))?;
    if res.status != 200 {
        return Err(SyncError::Status(res.status));
    }
    Ok(res.body)
}

fn cursor(store: &Store) -> Result<u64, SyncError> {
    Ok(store
        .meta_get(CURSOR)?
        .and_then(|b| String::from_utf8(b).ok()?.parse().ok())
        .unwrap_or(0))
}

/// Store a verified remote record. Against an unpushed local edit it is merged, never simply
/// preferred by hlc, so concurrent edits to different fields both survive.
fn apply(
    store: &Store,
    clock: &mut Clock,
    now_ms: u64,
    merge: Merge,
    rec: Record,
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    let local = match store.get(&rec.id)? {
        Some(l) if l.hlc != rec.hlc && store.is_pending(&rec.id)? => l,
        _ => {
            if store.put_remote(&rec)? {
                report.applied += 1;
            }
            return Ok(());
        }
    };
    // The remote stamp was observed above, so the fresh one is newer than both copies.
    let fresh = clock.tick(store, now_ms)?;
    match merge(&local, &rec, &fresh)? {
        Resolution::Keep => store.rebase(&rec.id, Some(&rec.hlc))?,
        Resolution::Take => {
            store.replace(&rec)?;
            report.applied += 1;
        }
        Resolution::Write(merged) => {
            if merged.id != rec.id || merged.hlc != fresh {
                return Err(SyncError::Protocol("merge returned a foreign record"));
            }
            store.put_merged(&merged, &rec.hlc)?;
            report.merged += 1;
        }
    }
    Ok(())
}

/// Pull every page after the stored cursor and apply it.
fn pull(
    store: &Store,
    clock: &mut Clock,
    t: &dyn Transport,
    device: &Device,
    now_ms: u64,
    (verify, merge): (Verify, Merge),
    report: &mut SyncReport,
) -> Result<(), SyncError> {
    for _ in 0..MAX_PAGES {
        let before = cursor(store)?;
        let path = format!("/v1/pull?cursor={before}&limit={PULL_LIMIT}");
        let page: PullResp =
            serde_json::from_slice(&call(t, device, now_ms, "GET", &path, Vec::new())?)
                .map_err(|_| SyncError::Protocol("pull response"))?;
        for w in page.records {
            report.pulled += 1;
            let blob = unb64(&w.blob).filter(|b| b.len() <= MAX_BLOB_BYTES);
            let ids_ok =
                (1..=MAX_ID_LEN).contains(&w.id.len()) && (1..=MAX_ID_LEN).contains(&w.vault.len());
            let Some(blob) = blob.filter(|_| ids_ok) else {
                report.rejected += 1;
                continue;
            };
            // Observing first also validates the stamp; a bad one never reaches the store.
            if !clock.observe(&w.hlc, now_ms) {
                report.rejected += 1;
                continue;
            }
            let rec = Record {
                id: w.id,
                vault: w.vault,
                hlc: w.hlc,
                tombstone: w.tomb,
                blob,
            };
            match verify(&rec) {
                Verdict::Accept => {}
                Verdict::Reject => {
                    report.rejected += 1;
                    continue;
                }
                // the cursor stays where it was; earlier records of this page re-apply as no-ops
                Verdict::Defer => return Err(SyncError::Deferred),
            }
            apply(store, clock, now_ms, merge, rec, report)?;
        }
        clock.persist(store)?;
        store.meta_set(CURSOR, page.cursor.to_string().as_bytes())?;
        if !page.more {
            return Ok(());
        }
        if page.cursor <= before {
            return Err(SyncError::Protocol("pull cursor did not advance"));
        }
    }
    Err(SyncError::Protocol("too many pull pages"))
}

/// Push pending edits. Returns whether every one was accepted.
fn push(
    store: &Store,
    t: &dyn Transport,
    device: &Device,
    now_ms: u64,
    report: &mut SyncReport,
) -> Result<bool, SyncError> {
    let pending = store.pending()?;
    let mut clean = true;
    for chunk in pending.chunks(PUSH_BATCH) {
        let records: Vec<_> = chunk
            .iter()
            .map(|(r, base)| {
                serde_json::json!({
                    "id": r.id, "vault": r.vault, "hlc": r.hlc, "tomb": r.tombstone,
                    "blob": b64(&r.blob), "base": base,
                })
            })
            .collect();
        let body = serde_json::json!({ "records": records })
            .to_string()
            .into_bytes();
        let res: PushResp =
            serde_json::from_slice(&call(t, device, now_ms, "POST", "/v1/push", body)?)
                .map_err(|_| SyncError::Protocol("push response"))?;
        for id in &res.accepted {
            let rec = chunk.iter().find(|(r, _)| &r.id == id);
            store.ack(
                id,
                &rec.ok_or(SyncError::Protocol("accepted unknown id"))?.0.hlc,
            )?;
            report.pushed += 1;
        }
        for c in res.conflicts {
            report.conflicts += 1;
            clean = false;
            // Next round pulls first (which replaces our edit if the relay copy is newer);
            // otherwise we push again against what the relay holds now.
            match c.current {
                Some(cur) if hlc::parse(&cur.hlc).is_some() => {
                    store.rebase(&c.id, Some(&cur.hlc))?
                }
                // The relay holds nothing (wiped or rebuilt): push as a new record.
                None => store.rebase(&c.id, None)?,
                Some(_) => {}
            }
        }
    }
    Ok(clean)
}

/// Bring the local store and the relay level. Needs no unlocked session.
pub fn sync(
    store: &Store,
    clock: &mut Clock,
    transport: &dyn Transport,
    device: &Device,
    now_ms: u64,
    verify: Verify,
    merge: Merge,
) -> Result<SyncReport, SyncError> {
    let mut report = SyncReport::default();
    for _ in 0..MAX_ROUNDS {
        pull(
            store,
            clock,
            transport,
            device,
            now_ms,
            (verify, merge),
            &mut report,
        )?;
        if push(store, transport, device, now_ms, &mut report)? {
            return Ok(report);
        }
    }
    Err(SyncError::Unsettled)
}
