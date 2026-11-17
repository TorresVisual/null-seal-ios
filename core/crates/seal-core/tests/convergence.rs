//! Convergence simulation (#42): N replicas make random edits, go offline and sync through a
//! network that drops, duplicates and reorders requests. Once the network heals, every replica
//! (and a late joiner that pulls from scratch) must hold the same records.
//!
//! The replicas are the real thing: a `Store`, an HLC `Clock`, `core_sync::sync` against the
//! in-memory relay, and the same verify/merge callbacks `Account::sync` uses. Only the vault key
//! is shared, so the Argon2 unlock happens once per thread instead of once per replica.
//!
//! Every run is a pure function of its seed. A failure prints the seed and the operation trace;
//! replay it with `CONVERGENCE_SEED=<n> cargo test -p seal-core --test convergence`.
//! `CONVERGENCE_RUNS` overrides the number of seeds (default 10 000).

#![allow(clippy::unwrap_used)]

use core_crypto::{KdfParams, Key};
use core_keys::{
    MasterHeader, Wrapper, new_account_key, new_vault_key, wrap_account_key, wrap_vault_key,
};
use core_store::{Record, Store};
use core_sync::mock::MockRelay;
use core_sync::{
    Clock, Device, Request, Response, SyncError, Transport, TransportError, register_first_device,
};
use core_vault::merge::stamp_changes;
use core_vault::{Item, Payload, Url};
use seal_core::account::{merge_records, verify_record};
use seal_core::session::{Session, VaultEntry};
use serde_json::Value;
use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;

const NOW: u64 = 1_800_000_000_000;
const VAULT: &str = "v1";
const PW: &str = "correct horse battery";
const DEFAULT_RUNS: u64 = 10_000;

/// splitmix64: tiny, seedable and identical on every platform.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// An unlocked session over one vault; replicas share it (they share the vault key anyway).
fn session() -> Session {
    let ak = new_account_key().unwrap();
    let header = MasterHeader::new(KdfParams::new(19 * 1024, 2, 1).unwrap()).unwrap();
    let wrapper = Wrapper::Master {
        password: PW,
        header: &header,
    };
    let ak_wrapper = wrap_account_key(&ak, &wrapper).unwrap();
    let vk = new_vault_key().unwrap();
    let vaults = [VaultEntry {
        id: VAULT.into(),
        key_gen: 2,
        wrapped_key: wrap_vault_key(&ak, 0, VAULT.as_bytes(), 2, &vk).unwrap(),
        old: vec![],
    }];
    let mut s = Session::new();
    s.unlock(
        0,
        &Store::open_in_memory().unwrap(),
        &wrapper,
        &ak_wrapper,
        &vaults,
    )
    .unwrap();
    s
}

/// The network between every replica and the relay.
struct Chaos {
    relay: MockRelay,
    rng: RefCell<Rng>,
    /// Pushes that were lost in flight and may still arrive, long after newer ones.
    late: RefCell<Vec<Request>>,
    /// Faults are off while the network heals.
    faulty: Cell<bool>,
}

fn copy(r: &Request) -> Request {
    Request {
        method: r.method,
        path: r.path.clone(),
        headers: r.headers.clone(),
        body: r.body.clone(),
    }
}

/// One replica's view of the network.
struct Net<'a> {
    chaos: &'a Chaos,
    partitioned: bool,
}

impl Transport for Net<'_> {
    fn send(&self, r: &Request) -> Result<Response, TransportError> {
        let c = self.chaos;
        let down = || Err(TransportError("network down".into()));
        if self.partitioned {
            return down();
        }
        if !c.faulty.get() {
            return c.relay.send(r);
        }
        let roll = c.rng.borrow_mut().below(100);
        match roll {
            // request lost; a push may still show up later
            0..=9 => {
                if r.method == "POST" && c.rng.borrow_mut().below(2) == 0 {
                    c.late.borrow_mut().push(copy(r));
                }
                down()
            }
            // the relay applied it but the answer was lost
            10..=19 => {
                let _ = c.relay.send(r);
                down()
            }
            // delivered twice
            20..=29 => {
                let _ = c.relay.send(r);
                c.relay.send(r)
            }
            // an old, lost push arrives just before this request
            30..=44 => {
                let old = {
                    let mut late = c.late.borrow_mut();
                    let n = late.len();
                    (n > 0).then(|| late.swap_remove(c.rng.borrow_mut().below(n)))
                };
                if let Some(old) = old {
                    let _ = c.relay.send(&old);
                }
                c.relay.send(r)
            }
            _ => c.relay.send(r),
        }
    }
}

struct Replica {
    name: String,
    store: Store,
    clock: Clock,
    device: Device,
    /// This replica's wall clock; skewed from the others and mostly stuck in the same millisecond.
    now: u64,
    partitioned: bool,
}

impl Replica {
    fn new(node: u32, now: u64) -> Self {
        let store = Store::open_in_memory().unwrap();
        let clock = Clock::load(&store, node).unwrap();
        Self {
            name: format!("r{node}"),
            store,
            clock,
            // one relay identity for all replicas: the relay only checks the signature
            device: Device {
                id: "dev".into(),
                seed: Key::from_bytes([7; 32]),
            },
            now,
            partitioned: false,
        }
    }

    fn sync(&mut self, s: &Session, chaos: &Chaos) -> Result<(), SyncError> {
        let net = Net {
            chaos,
            partitioned: self.partitioned,
        };
        core_sync::sync(
            &self.store,
            &mut self.clock,
            &net,
            &self.device,
            self.now,
            &|rec| verify_record(s, rec),
            &|l, r, fresh| merge_records(s, l, r, fresh),
        )
        .map(drop)
    }

    /// Write a new revision of `id` (or a new item) as `Account::save_login` does.
    fn edit(&mut self, s: &Session, id: &str, f: impl FnOnce(&mut Payload)) -> (String, Payload) {
        let old = self
            .store
            .get(id)
            .unwrap()
            .filter(|r| !r.tombstone)
            .map(|r| s.open_record(&r).unwrap());
        let mut new = old
            .clone()
            .unwrap_or_else(|| Payload::new_login(Default::default()));
        f(&mut new);
        let hlc = self.clock.tick(&self.store, self.now).unwrap();
        stamp_changes(old.as_ref(), &mut new, &hlc);
        let rec = s.seal_record(VAULT, id, &hlc, false, &new).unwrap();
        self.store.put_local(&rec).unwrap();
        (hlc, new)
    }

    fn delete(&mut self, s: &Session, id: &str) -> String {
        let hlc = self.clock.tick(&self.store, self.now).unwrap();
        let rec = s
            .seal_record(VAULT, id, &hlc, true, &Payload::tombstone(&hlc))
            .unwrap();
        self.store.put_local(&rec).unwrap();
        hlc
    }

    fn live(&self, id: &str) -> bool {
        self.store.get(id).unwrap().is_some_and(|r| !r.tombstone)
    }
}

/// What the merge promises, stated independently of how it is implemented: per field (and per
/// tag / url) the write with the newest HLC wins, and a delete drops every write stamped at or
/// before it. Built from the edits as they were made, checked against the converged state, so
/// a merge that converges by quietly dropping someone's edit still fails.
#[derive(Default)]
struct Oracle {
    /// (item, field key as in `fields_hlc`) -> (hlc, value written; `None` = cleared/removed)
    writes: BTreeMap<(String, String), (String, Option<Value>)>,
    deletes: BTreeMap<String, String>,
}

impl Oracle {
    fn edit(&mut self, id: &str, hlc: &str, p: &Payload) {
        let data = serde_json::to_value(&p.data).unwrap();
        for (key, stamp) in p.fields_hlc.iter().filter(|(_, st)| *st == hlc) {
            let value = match key.split_once(':') {
                Some(("tags", t)) => data["tags"]
                    .as_array()
                    .and_then(|a| a.iter().find(|v| v.as_str() == Some(t)).cloned()),
                Some(("urls", u)) => data["urls"]
                    .as_array()
                    .and_then(|a| a.iter().find(|v| v["url"].as_str() == Some(u)).cloned()),
                _ => data.get(key).cloned(),
            };
            let slot = self.writes.entry((id.to_owned(), key.clone()));
            let newer = |old: &(String, Option<Value>)| old.0 < *stamp;
            slot.and_modify(|old| {
                if newer(old) {
                    *old = (stamp.clone(), value.clone());
                }
            })
            .or_insert((stamp.clone(), value));
        }
    }

    fn delete(&mut self, id: &str, hlc: String) {
        let d = self.deletes.entry(id.to_owned()).or_default();
        *d = (*d).clone().max(hlc);
    }

    /// `None` if `actual` (the converged record, `None` = missing) is what the writes imply.
    fn check(&self, id: &str, actual: Option<&(String, bool, Payload)>) -> Option<String> {
        let barrier = self.deletes.get(id).map_or("", String::as_str);
        let writes: Vec<_> = self
            .writes
            .iter()
            .filter(|((i, _), _)| i == id)
            .map(|((_, k), (st, v))| (k, st, v))
            .collect();
        let Some((_, tombstone, p)) = actual else {
            return Some(format!("{id}: missing"));
        };
        let survives = writes.iter().any(|(_, st, _)| st.as_str() > barrier);
        if !survives {
            return (!barrier.is_empty() && !tombstone)
                .then(|| format!("{id}: deleted at {barrier} but still alive"));
        }
        if *tombstone {
            return Some(format!(
                "{id}: tombstone, but a write is newer than the delete {barrier}"
            ));
        }
        let data = serde_json::to_value(&p.data).unwrap();
        let default = serde_json::to_value(Item::default()).unwrap();
        for (key, stamp, value) in writes {
            let live = stamp.as_str() > barrier;
            let (got, want) = match key.split_once(':') {
                Some(("tags", t)) => (
                    data["tags"]
                        .as_array()
                        .and_then(|a| a.iter().find(|v| v.as_str() == Some(t)))
                        .cloned(),
                    value.clone().filter(|_| live),
                ),
                Some(("urls", u)) => (
                    data["urls"]
                        .as_array()
                        .and_then(|a| a.iter().find(|v| v["url"].as_str() == Some(u)))
                        .cloned(),
                    value.clone().filter(|_| live),
                ),
                _ => (
                    data.get(key).cloned(),
                    if live {
                        value.clone()
                    } else {
                        default.get(key).cloned()
                    },
                ),
            };
            if got != want {
                return Some(format!(
                    "{id}.{key}: write {stamp} (delete {barrier:?}) expects {want:?}, replicas hold {got:?}"
                ));
            }
        }
        None
    }
}

/// What a replica holds, readable: id -> (hlc, tombstone, payload).
fn snapshot(s: &Session, r: &Replica) -> BTreeMap<String, (String, bool, Payload)> {
    r.store
        .list(VAULT)
        .unwrap()
        .into_iter()
        .map(|rec: Record| {
            let p = s.open_record(&rec).unwrap();
            (rec.id, (rec.hlc, rec.tombstone, p))
        })
        .collect()
}

fn word(rng: &mut Rng, prefix: &str) -> String {
    // a tiny vocabulary, so concurrent edits keep hitting the same values and fields
    format!("{prefix}{}", rng.below(3))
}

/// One random local edit of a live item; returns what it did, for the trace.
fn random_edit(rng: &mut Rng, p: &mut Payload) -> String {
    let d = &mut p.data;
    d.updated_at += 1;
    match rng.below(9) {
        0 => {
            d.title = word(rng, "title");
            format!("title={}", d.title)
        }
        1 => {
            d.username = (rng.below(4) > 0).then(|| word(rng, "user"));
            format!("username={:?}", d.username)
        }
        2 => {
            d.password = (rng.below(4) > 0).then(|| word(rng, "pw"));
            format!("password={:?}", d.password)
        }
        3 => {
            d.notes = (rng.below(4) > 0).then(|| word(rng, "note"));
            format!("notes={:?}", d.notes)
        }
        4 => {
            d.favorite = !d.favorite;
            format!("favorite={}", d.favorite)
        }
        5 => {
            let t = word(rng, "tag");
            if !d.tags.contains(&t) {
                d.tags.push(t.clone());
            }
            format!("tag+{t}")
        }
        6 if !d.tags.is_empty() => {
            let t = d.tags.remove(rng.below(d.tags.len()));
            format!("tag-{t}")
        }
        7 => {
            let u = format!("https://{}.example", word(rng, "u"));
            if !d.urls.iter().any(|x| x.url == u) {
                d.urls.push(Url {
                    url: u.clone(),
                    ..Url::default()
                });
            }
            format!("url+{u}")
        }
        _ if !d.urls.is_empty() => {
            let u = d.urls.remove(rng.below(d.urls.len())).url;
            format!("url-{u}")
        }
        _ => "noop".into(),
    }
}

/// One simulation. `Err` carries the reason and the trace.
fn run(seed: u64, s: &Session) -> Result<(), String> {
    let mut rng = Rng(seed);
    let n = 2 + rng.below(3);
    let chaos = Chaos {
        relay: MockRelay::new(NOW),
        rng: RefCell::new(Rng(rng.next())),
        late: RefCell::default(),
        faulty: Cell::new(true),
    };
    let mut reps: Vec<Replica> = (0..n)
        .map(|i| {
            // wall clocks disagree by up to +-2.5 minutes (the relay tolerates 5)
            let skew = rng.below(300_000) as u64;
            Replica::new(i as u32 + 1, NOW + skew - 150_000)
        })
        .collect();
    register_first_device(&chaos.relay, &reps[0].device, "setup").unwrap();

    let mut trace = Vec::new();
    let mut oracle = Oracle::default();
    let mut created = 0;
    let fail =
        |what: String, trace: &[String]| Err(format!("{what}\ntrace:\n  {}", trace.join("\n  ")));

    for _ in 0..25 + rng.below(40) {
        let i = rng.below(n);
        reps[i].now += rng.below(3) as u64; // often the same millisecond as the last op
        let (op, id) = (rng.below(100), format!("item{}", rng.below(3)));
        let name = reps[i].name.clone();
        match op {
            // create an item nobody has seen yet
            0..=7 if created < 3 => {
                let id = format!("item{created}");
                created += 1;
                let mut note = String::new();
                let (hlc, p) = reps[i].edit(s, &id, |p| {
                    p.data.title = word(&mut rng, "title");
                    note = p.data.title.clone();
                });
                oracle.edit(&id, &hlc, &p);
                trace.push(format!("{name} create {id} title={note}"));
            }
            8..=11 => {
                if reps[i].live(&id) {
                    let hlc = reps[i].delete(s, &id);
                    oracle.delete(&id, hlc);
                    trace.push(format!("{name} delete {id}"));
                }
            }
            12..=64 => {
                if reps[i].live(&id) {
                    let mut what = String::new();
                    let (hlc, p) = reps[i].edit(s, &id, |p| what = random_edit(&mut rng, p));
                    oracle.edit(&id, &hlc, &p);
                    trace.push(format!("{name} edit {id} {what}"));
                }
            }
            65..=89 => {
                let r = reps[i].sync(s, &chaos);
                trace.push(format!(
                    "{name} sync -> {}",
                    r.as_ref().map_or_else(|e| e.to_string(), |()| "ok".into())
                ));
                // the network may fail; anything else is a bug
                if let Err(e) = r
                    && !matches!(e, SyncError::Transport(_) | SyncError::Unsettled)
                {
                    return fail(format!("{name}: sync failed: {e}"), &trace);
                }
            }
            _ => {
                reps[i].partitioned = !reps[i].partitioned;
                trace.push(format!("{name} partitioned={}", reps[i].partitioned));
            }
        }
    }

    // heal: no faults, everyone back online, sync until quiet
    chaos.faulty.set(false);
    trace.push("-- network heals".into());
    for r in &mut reps {
        r.partitioned = false;
    }
    for round in 0..4 {
        for r in &mut reps {
            if let Err(e) = r.sync(s, &chaos) {
                return fail(
                    format!("{}: sync failed after healing (round {round}): {e}", r.name),
                    &trace,
                );
            }
        }
    }

    // a replica that joins now and pulls everything from scratch must agree as well
    let mut late = Replica::new(99, reps[0].now);
    if let Err(e) = late.sync(s, &chaos) {
        return fail(format!("late joiner: sync failed: {e}"), &trace);
    }
    reps.push(late);

    let first = snapshot(s, &reps[0]);
    for r in &reps {
        if !r.store.pending().unwrap().is_empty() {
            return fail(format!("{} still has unpushed edits", r.name), &trace);
        }
        let snap = snapshot(s, r);
        if snap != first {
            return fail(
                format!(
                    "{} diverged from {}:\n{snap:#?}\nvs\n{first:#?}",
                    r.name, reps[0].name
                ),
                &trace,
            );
        }
    }
    // converged is not enough: nobody's edit may have been dropped on the way
    for id in oracle
        .writes
        .keys()
        .map(|(id, _)| id)
        .collect::<std::collections::BTreeSet<_>>()
    {
        if let Some(why) = oracle.check(id, first.get(id)) {
            return fail(format!("silent loss: {why}"), &trace);
        }
    }
    Ok(())
}

#[test]
fn replicas_converge_under_offline_reordering_and_duplicates() {
    if let Ok(seed) = std::env::var("CONVERGENCE_SEED") {
        let seed = seed.parse().unwrap();
        run(seed, &session()).unwrap_or_else(|e| panic!("seed {seed} did not converge: {e}"));
        return;
    }
    let runs = std::env::var("CONVERGENCE_RUNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RUNS);
    let threads = std::thread::available_parallelism().map_or(1, usize::from) as u64;
    let failures: Vec<String> = std::thread::scope(|scope| {
        (0..threads)
            .map(|t| {
                scope.spawn(move || {
                    let s = session();
                    (t..runs)
                        .step_by(threads as usize)
                        .filter_map(|seed| run(seed, &s).err().map(|e| format!("seed {seed}: {e}")))
                        .collect::<Vec<_>>()
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .flat_map(|h| h.join().unwrap())
            .collect()
    });
    assert!(
        failures.is_empty(),
        "{} of {runs} runs did not converge. Replay one with \
         CONVERGENCE_SEED=<n> cargo test -p seal-core --test convergence\n\n{}",
        failures.len(),
        failures[..failures.len().min(3)].join("\n\n")
    );
}
