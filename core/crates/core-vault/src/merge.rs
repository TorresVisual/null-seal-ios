//! Merge engine (#40): converge two copies of one record without silent loss.
//!
//! The record is sealed as a whole, so merging happens on decrypted payloads, on the device.
//! Every changed field carries the HLC of the edit that last wrote it (`Payload::fields_hlc`):
//!
//! * scalar fields are last-writer-wins registers keyed by field name; an unset field that was
//!   cleared keeps its stamp, so a clear beats an older value;
//! * `tags` and `urls` are add/remove sets: each element has its own stamp under `tags:<tag>` /
//!   `urls:<url>`, present in the list = added, absent with a stamp = removed;
//! * a delete is the barrier `$deleted` = the HLC of the delete: anything stamped at or before it
//!   is dropped, anything newer survives. A merge result with a barrier and no survivor is a
//!   tombstone. Unstamped (legacy) data counts as older than any stamp.
//!
//! The merge is commutative, associative and idempotent on content, so replicas that see the
//! same edits in any order or number of times end with the same payload. Ties (equal stamps are
//! the same write, or legacy data) resolve by the larger serialized value, add-wins for sets.
//!
//! History (#41) is a union of prior versions keyed by the HLC of the edit that replaced them,
//! newest first, capped at `HISTORY_MAX`; a deleted record keeps none.
//!
//! ponytail: opaque `extras` and unknown top-level keys come wholesale from the side with the
//! newer record HLC; per-key stamps for them if an import needs concurrent extras edits.

use crate::{HISTORY_MAX, Item, Payload, Version};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};

/// Stamp key of the delete barrier in `fields_hlc`.
pub const DELETED: &str = "$deleted";
const SETS: [&str; 2] = ["tags", "urls"];

/// One copy of a record as the merge sees it.
pub struct Side<'a> {
    pub hlc: &'a str,
    pub tombstone: bool,
    pub payload: &'a Payload,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Merged {
    /// The local copy already holds everything and its HLC is ahead: keep it.
    Local,
    /// The remote copy already holds everything: adopt it, drop the local edit.
    Remote,
    /// Neither copy is the answer: seal this under a fresh HLC and push it.
    New {
        payload: Box<Payload>,
        tombstone: bool,
    },
}

pub fn merge(local: &Side, remote: &Side) -> Merged {
    let (l, r) = (normalize(local), normalize(remote));
    let ahead = local.hlc > remote.hlc;
    let (payload, tombstone) = combine(&l, &r, ahead);
    if (&payload, tombstone) == as_ref(&combine(&r, &r, true)) {
        Merged::Remote
    } else if ahead && (&payload, tombstone) == as_ref(&combine(&l, &l, true)) {
        Merged::Local
    } else {
        Merged::New {
            payload: Box::new(payload),
            tombstone,
        }
    }
}

fn as_ref((p, t): &(Payload, bool)) -> (&Payload, bool) {
    (p, *t)
}

/// Record every field that differs between `old` and `new` as written at `hlc`, and keep `old`
/// as a history version if the edit changed anything but `updated_at`. Call it on each local
/// edit, before sealing; `old` is `None` for a new item.
pub fn stamp_changes(old: Option<&Payload>, new: &mut Payload, hlc: &str) {
    let o = old.map(|p| data_map(&p.data)).unwrap_or_default();
    let n = data_map(&new.data);
    if let Some(old) = old {
        let same = |m: &Map<String, Value>| {
            let mut m = m.clone();
            m.remove("updated_at");
            m
        };
        let mut history = old.history.clone();
        if same(&o) != same(&n) {
            history.push(Version {
                at: hlc.to_owned(),
                data: old.data.clone(),
            });
        }
        new.history = union_history(&history, &[]);
    }
    for k in o.keys().chain(n.keys()) {
        if !SETS.contains(&k.as_str()) && o.get(k) != n.get(k) {
            new.fields_hlc.insert(k.clone(), hlc.to_owned());
        }
    }
    for set in SETS {
        let (oe, ne) = (elements(&o, set), elements(&n, set));
        for k in oe.keys().chain(ne.keys()) {
            if oe.get(k) != ne.get(k) {
                new.fields_hlc.insert(k.clone(), hlc.to_owned());
            }
        }
    }
}

fn data_map(i: &Item) -> Map<String, Value> {
    match serde_json::to_value(i) {
        Ok(Value::Object(m)) => m,
        _ => Map::new(),
    }
}

/// Set elements keyed by their `fields_hlc` name (`tags:rust`, `urls:https://…`).
fn elements<'a>(m: &'a Map<String, Value>, set: &str) -> BTreeMap<String, &'a Value> {
    m.get(set)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|v| {
            let key = if set == "tags" {
                v.as_str()?
            } else {
                v.get("url")?.as_str()?
            };
            Some((format!("{set}:{key}"), v))
        })
        .collect()
}

/// Both histories merged: unique by `at`, newest first, capped.
fn union_history(a: &[Version], b: &[Version]) -> Vec<Version> {
    let mut all: Vec<Version> = a.iter().chain(b).cloned().collect();
    all.sort_by(|x, y| y.at.cmp(&x.at));
    all.dedup_by(|x, y| x.at == y.at);
    all.truncate(HISTORY_MAX);
    all
}

/// A tombstone side becomes an empty payload holding only its barrier.
fn normalize(s: &Side) -> Payload {
    let mut p = s.payload.clone();
    if s.tombstone {
        let barrier = p
            .fields_hlc
            .get(DELETED)
            .map_or_else(|| s.hlc.to_owned(), Clone::clone);
        p.data = Item::default();
        p.history.clear();
        p.extras.clear();
        p.unknown.clear();
        p.fields_hlc = BTreeMap::from([(DELETED.to_owned(), barrier)]);
    }
    p
}

/// The newer stamp wins; on a tie, whichever side holds a value, then the larger value.
fn pick<'a>(
    (ls, lv): (&str, Option<&'a Value>),
    (rs, rv): (&str, Option<&'a Value>),
) -> Option<&'a Value> {
    match ls.cmp(rs) {
        core::cmp::Ordering::Greater => lv,
        core::cmp::Ordering::Less => rv,
        core::cmp::Ordering::Equal => match (lv, rv) {
            (Some(a), Some(b)) => {
                let (sa, sb) = (a.to_string(), b.to_string());
                Some(if sa >= sb { a } else { b })
            }
            (a, b) => a.or(b),
        },
    }
}

/// A `fields_hlc` name of a set element (`tags:…`, `urls:…`), as opposed to a scalar field.
fn is_element(k: &str) -> bool {
    SETS.iter()
        .any(|s| k.strip_prefix(s).is_some_and(|r| r.starts_with(':')))
}

fn stamp<'a>(p: &'a Payload, k: &str) -> &'a str {
    p.fields_hlc.get(k).map_or("", String::as_str)
}

/// Merge two normalized payloads; the flag says whether the result is a tombstone. Top-level
/// metadata (`extras`, unknown keys) comes from `l` when `meta_from_l`.
fn combine(l: &Payload, r: &Payload, meta_from_l: bool) -> (Payload, bool) {
    let (ld, rd) = (data_map(&l.data), data_map(&r.data));
    let barrier = stamp(l, DELETED).max(stamp(r, DELETED));
    let dead = |s: &str| !barrier.is_empty() && s <= barrier;
    let mut stamps = BTreeMap::new();
    let mut data = Map::new();

    // scalar registers: every data key, plus cleared fields that only survive as a stamp
    let keys: BTreeSet<&str> = ld
        .keys()
        .chain(rd.keys())
        .chain(l.fields_hlc.keys())
        .chain(r.fields_hlc.keys())
        .map(String::as_str)
        .filter(|k| *k != DELETED && !SETS.contains(k) && !is_element(k))
        .collect();
    for k in keys {
        let (ls, rs) = (stamp(l, k), stamp(r, k));
        let newest = ls.max(rs);
        if dead(newest) {
            continue;
        }
        if let Some(v) = pick((ls, ld.get(k)), (rs, rd.get(k))) {
            data.insert(k.to_owned(), v.clone());
        }
        if !newest.is_empty() {
            stamps.insert(k.to_owned(), newest.to_owned());
        }
    }

    // sets: ordered by (stamp, element) so the first-added url stays the primary one
    for set in SETS {
        let (le, re) = (elements(&ld, set), elements(&rd, set));
        let prefix = format!("{set}:");
        let names: BTreeSet<&str> = le
            .keys()
            .chain(re.keys())
            .chain(l.fields_hlc.keys().filter(|k| k.starts_with(&prefix)))
            .chain(r.fields_hlc.keys().filter(|k| k.starts_with(&prefix)))
            .map(String::as_str)
            .collect();
        let mut live = Vec::new();
        for name in names {
            let (ls, rs) = (stamp(l, name), stamp(r, name));
            let newest = ls.max(rs);
            if dead(newest) {
                continue;
            }
            if let Some(v) = pick((ls, le.get(name).copied()), (rs, re.get(name).copied())) {
                live.push((newest, name, v));
            }
            if !newest.is_empty() {
                stamps.insert(name.to_owned(), newest.to_owned());
            }
        }
        live.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
        if !live.is_empty() {
            data.insert(
                set.to_owned(),
                Value::Array(live.into_iter().map(|(_, _, v)| v.clone()).collect()),
            );
        }
    }

    let tombstone = !barrier.is_empty() && stamps.is_empty();
    if !barrier.is_empty() {
        stamps.insert(DELETED.to_owned(), barrier.to_owned());
    }
    let base = if meta_from_l { l } else { r };
    let mut merged = Payload {
        fields_hlc: stamps,
        data: if tombstone {
            Item::default()
        } else {
            serde_json::from_value(Value::Object(data)).unwrap_or_default()
        },
        ..base.clone()
    };
    if tombstone {
        // a deleted record keeps no imported secrets
        merged.extras.clear();
        merged.unknown.clear();
    } else {
        merged.history = union_history(&l.history, &r.history);
    }
    (merged, tombstone)
}

#[cfg(test)]
mod tests;
