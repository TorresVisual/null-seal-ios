//! In-memory stand-in for the relay (same semantics as `relay/src/index.ts`) so sync and
//! enrollment can be tested without a network. The real Worker is exercised end to end by
//! the harness in #39. Test support only: enabled by the `mock` feature.

use crate::{Request, Response, Transport, TransportError, hex};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use core_crypto::{sha256, verify};
use serde_json::{Value, json};
use std::cell::{Cell, RefCell};
use std::collections::HashMap;

const ENROLL_TTL_MS: u64 = 10 * 60_000;
const SKEW_MS: u64 = 5 * 60_000;

#[derive(Clone)]
struct Rec {
    id: String,
    vault: String,
    hlc: String,
    tomb: bool,
    blob: String,
    seq: u64,
}

impl Rec {
    fn wire(&self) -> Value {
        json!({"id": self.id, "vault": self.vault, "hlc": self.hlc, "tomb": self.tomb, "blob": self.blob, "seq": self.seq})
    }
}

struct Session {
    created_by: String,
    expires: u64,
    request: Option<Value>,
    response: Option<Value>,
}

struct Dev {
    pubkey: [u8; 32],
    created_at: u64,
    last_seen: Option<u64>,
    attest: Option<String>,
    rekey: Option<String>,
}

impl Dev {
    fn new(pubkey: [u8; 32], created_at: u64) -> Self {
        Self {
            pubkey,
            created_at,
            last_seen: None,
            attest: None,
            rekey: None,
        }
    }
}

#[derive(Default)]
struct State {
    devices: HashMap<String, Dev>,
    records: Vec<Rec>,
    sessions: HashMap<String, Session>,
    /// Account-auth public key (#124).
    account: Option<[u8; 32]>,
    /// R2 backups (#47): (key, uploaded ms, stored text); `None` = R2 not enabled on this relay.
    backups: Vec<(String, u64, String)>,
    backup_seq: u32,
}

pub struct MockRelay {
    state: RefCell<State>,
    pub setup_token: String,
    /// Whether the owner enabled R2 backups on this relay.
    pub backups_enabled: Cell<bool>,
    /// Relay's clock; tests move it to expire enrollment sessions.
    pub now_ms: Cell<u64>,
    /// Every request seen, for assertions about what crossed the wire.
    pub log: RefCell<Vec<String>>,
}

impl MockRelay {
    pub fn new(now_ms: u64) -> Self {
        Self {
            state: RefCell::default(),
            setup_token: "setup".into(),
            backups_enabled: Cell::new(true),
            now_ms: Cell::new(now_ms),
            log: RefCell::default(),
        }
    }

    /// Everything the relay stores or saw, as one string (for "no plaintext" checks).
    pub fn dump(&self) -> String {
        self.log.borrow().join("\n")
    }

    pub fn record_count(&self) -> usize {
        self.state.borrow().records.len()
    }
}

fn res(status: u16, body: Value) -> Result<Response, TransportError> {
    Ok(Response {
        status,
        body: body.to_string().into_bytes(),
    })
}

fn header<'a>(r: &'a Request, name: &str) -> Option<&'a str> {
    r.headers
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v.as_str())
}

fn key32(v: &Value) -> Option<[u8; 32]> {
    B64.decode(v.as_str()?).ok()?.try_into().ok()
}

fn account_of(v: &Value) -> Option<[u8; 32]> {
    key32(&v["pubkey"])
}

impl Transport for MockRelay {
    fn send(&self, r: &Request) -> Result<Response, TransportError> {
        self.log.borrow_mut().push(format!(
            "{} {} {:?} {}",
            r.method,
            r.path,
            r.headers,
            String::from_utf8_lossy(&r.body)
        ));
        let now = self.now_ms.get();
        let mut st = self.state.borrow_mut();
        let body: Value = serde_json::from_slice(&r.body).unwrap_or(Value::Null);
        let (path, query) = r.path.split_once('?').unwrap_or((&r.path, ""));

        if path == "/v1/bootstrap" {
            let ok = header(r, "x-setup-token") == Some(self.setup_token.as_str())
                && st.devices.is_empty();
            let (Some(id), Some(pk)) = (body["device_id"].as_str(), key32(&body["pubkey"])) else {
                return res(400, json!({}));
            };
            if !ok {
                return res(401, json!({}));
            }
            st.devices.insert(id.to_owned(), Dev::new(pk, now));
            return res(201, json!({"ok": true}));
        }

        if (r.method, path) == ("POST", "/v1/devices/recover") {
            let (Some(id), Some(pk), Some(ts), Some(sig)) = (
                body["device_id"].as_str(),
                key32(&body["pubkey"]),
                body["ts"].as_u64(),
                body["sig"]
                    .as_str()
                    .and_then(|s| B64.decode(s).ok())
                    .and_then(|b| <[u8; 64]>::try_from(b).ok()),
            ) else {
                return res(400, json!({}));
            };
            let msg = format!("null-seal-v1\nrecover\n{id}\n{}\n{ts}", B64.encode(pk));
            let proven = st
                .account
                .is_some_and(|auth| verify(&auth, msg.as_bytes(), &sig))
                && ts.abs_diff(now) <= SKEW_MS;
            if !proven {
                return res(401, json!({}));
            }
            if st.devices.contains_key(id) {
                return res(409, json!({}));
            }
            st.devices.insert(id.to_owned(), Dev::new(pk, now));
            return res(201, json!({"ok": true}));
        }

        let parts: Vec<&str> = path.split('/').collect(); // "", v1, enroll, sid, action
        let open =
            parts.len() == 5 && parts[2] == "enroll" && matches!(parts[4], "request" | "result");
        let device = if open {
            None
        } else {
            let (Some(id), Some(ts), Some(sig)) =
                (header(r, "x-device"), header(r, "x-ts"), header(r, "x-sig"))
            else {
                return res(401, json!({}));
            };
            let ts_ms: u64 = ts.parse().unwrap_or(0);
            let msg = format!(
                "null-seal-v1\n{}\n{}\n{ts}\n{}",
                r.method,
                r.path,
                hex(&sha256(&r.body))
            );
            let sig: Option<[u8; 64]> = B64.decode(sig).ok().and_then(|b| b.try_into().ok());
            let valid = st
                .devices
                .get(id)
                .zip(sig)
                .is_some_and(|(d, sig)| verify(&d.pubkey, msg.as_bytes(), &sig))
                && ts_ms.abs_diff(now) <= SKEW_MS;
            if !valid {
                return res(401, json!({}));
            }
            if let Some(d) = st.devices.get_mut(id) {
                d.last_seen = Some(now);
            }
            Some(id.to_owned())
        };

        match (r.method, path) {
            ("POST", "/v1/push") => {
                let list = body["records"].as_array().cloned().unwrap_or_default();
                let (mut accepted, mut conflicts) = (Vec::new(), Vec::new());
                for it in list {
                    let id = it["id"].as_str().unwrap_or_default().to_owned();
                    let hlc = it["hlc"].as_str().unwrap_or_default().to_owned();
                    let base = it["base"].as_str();
                    let cur = st.records.iter().position(|x| x.id == id);
                    let writable = match cur {
                        None => true,
                        Some(i) => {
                            Some(st.records[i].hlc.as_str()) == base && hlc > st.records[i].hlc
                        }
                    };
                    if writable {
                        let seq = st.records.iter().map(|x| x.seq).max().unwrap_or(0) + 1;
                        let rec = Rec {
                            id: id.clone(),
                            vault: it["vault"].as_str().unwrap_or_default().to_owned(),
                            hlc,
                            tomb: it["tomb"].as_bool().unwrap_or(false),
                            blob: it["blob"].as_str().unwrap_or_default().to_owned(),
                            seq,
                        };
                        match cur {
                            Some(i) => st.records[i] = rec,
                            None => st.records.push(rec),
                        }
                        accepted.push(id);
                    } else if cur.is_some_and(|i| st.records[i].hlc == hlc) {
                        accepted.push(id);
                    } else {
                        let current = cur.map(|i| st.records[i].wire());
                        conflicts.push(json!({"id": id, "current": current}));
                    }
                }
                res(200, json!({"accepted": accepted, "conflicts": conflicts}))
            }
            ("GET", "/v1/pull") => {
                let q = |k: &str| {
                    query.split('&').find_map(|p| {
                        p.strip_prefix(&format!("{k}="))
                            .and_then(|v| v.parse::<u64>().ok())
                    })
                };
                let (cursor, limit) = (
                    q("cursor").unwrap_or(0),
                    q("limit").unwrap_or(100).min(100) as usize,
                );
                let mut recs: Vec<&Rec> = st.records.iter().filter(|x| x.seq > cursor).collect();
                recs.sort_by_key(|x| x.seq);
                let more = recs.len() > limit;
                recs.truncate(limit);
                let cursor = recs.last().map_or(cursor, |x| x.seq);
                res(
                    200,
                    json!({"records": recs.iter().map(|x| x.wire()).collect::<Vec<_>>(), "cursor": cursor, "more": more}),
                )
            }
            ("GET", "/v1/devices") => {
                let mut rows: Vec<_> = st.devices.iter().collect();
                rows.sort_by_key(|(id, d)| (d.created_at, (*id).clone()));
                let devices: Vec<_> = rows
                    .iter()
                    .map(|(id, d)| json!({"id": id, "pubkey": B64.encode(d.pubkey), "created_at": d.created_at, "last_seen": d.last_seen, "attest": d.attest}))
                    .collect();
                res(200, json!({ "devices": devices }))
            }
            ("PUT", "/v1/devices/me") => {
                let (Some(a), Some(me)) = (body["attest"].as_str(), device) else {
                    return res(400, json!({}));
                };
                if let Some(d) = st.devices.get_mut(&me) {
                    d.attest = Some(a.to_owned());
                }
                res(200, json!({"ok": true}))
            }
            ("PUT", "/v1/backup") => {
                if !self.backups_enabled.get() {
                    return res(501, json!({}));
                }
                let text = String::from_utf8_lossy(&r.body).into_owned();
                if text.is_empty() {
                    return res(400, json!({}));
                }
                if text.len() > 4 << 20 {
                    return res(413, json!({}));
                }
                st.backup_seq += 1;
                let key = format!("{now:013}-{:08x}", st.backup_seq);
                st.backups.push((key.clone(), now, text));
                st.backups.sort_by(|a, b| b.0.cmp(&a.0));
                st.backups.truncate(10);
                res(201, json!({"key": key}))
            }
            ("GET", "/v1/backup") if self.backups_enabled.get() => {
                let list: Vec<_> = st
                    .backups
                    .iter()
                    .map(|(k, at, t)| json!({"key": k, "size": t.len(), "uploaded": at}))
                    .collect();
                res(200, json!({ "backups": list }))
            }
            ("GET", p) if p.starts_with("/v1/backup/") && self.backups_enabled.get() => {
                match st
                    .backups
                    .iter()
                    .find(|(k, ..)| k == &p["/v1/backup/".len()..])
                {
                    Some((_, _, t)) => Ok(Response {
                        status: 200,
                        body: t.clone().into_bytes(),
                    }),
                    None => res(404, json!({})),
                }
            }
            ("PUT" | "GET", p) if p.starts_with("/v1/backup") => res(501, json!({})),
            ("PUT", "/v1/account") => {
                let Some(next) = account_of(&body) else {
                    return res(400, json!({}));
                };
                match st.account {
                    Some(cur) if cur != next => res(409, json!({})),
                    _ => {
                        st.account = Some(next);
                        res(200, json!({"ok": true}))
                    }
                }
            }
            ("POST", "/v1/rotate") => {
                let strs = |v: &Value| -> Vec<String> {
                    v.as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default()
                };
                let revoke = strs(&body["revoke"]);
                let rekey: Vec<(String, String)> = body["rekey"]
                    .as_object()
                    .map(|o| {
                        o.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default();
                let me = device.unwrap_or_default();
                let mut want: Vec<&String> =
                    revoke.iter().chain(rekey.iter().map(|(k, _)| k)).collect();
                want.sort();
                let mut have: Vec<&String> = st.devices.keys().collect();
                have.sort();
                let Some(next) = account_of(&body["account"]) else {
                    return res(400, json!({}));
                };
                if revoke.contains(&me) || !rekey.iter().any(|(k, _)| *k == me) || want != have {
                    return res(409, json!({}));
                }
                st.account = Some(next);
                for id in &revoke {
                    st.devices.remove(id);
                }
                for (id, blob) in rekey {
                    if let Some(d) = st.devices.get_mut(&id) {
                        d.rekey = Some(blob);
                    }
                }
                st.sessions.clear();
                res(200, json!({"ok": true}))
            }
            ("GET", "/v1/rekey") => {
                let blob = device.and_then(|me| st.devices.get(&me)?.rekey.clone());
                res(200, json!({ "rekey": blob }))
            }
            ("DELETE", "/v1/rekey") => {
                if let Some(d) = device.and_then(|me| st.devices.get_mut(&me)) {
                    d.rekey = None;
                }
                res(200, json!({"ok": true}))
            }
            ("POST", "/v1/enroll") => {
                let (Some(sid), Some(by)) = (body["sid"].as_str(), device) else {
                    return res(400, json!({}));
                };
                st.sessions.retain(|_, s| s.expires >= now);
                if st.sessions.contains_key(sid) {
                    return res(409, json!({}));
                }
                st.sessions.insert(
                    sid.to_owned(),
                    Session {
                        created_by: by,
                        expires: now + ENROLL_TTL_MS,
                        request: None,
                        response: None,
                    },
                );
                res(201, json!({}))
            }
            (m, _) if parts.len() >= 4 && parts[2] == "enroll" => {
                let sid = parts[3];
                let live = st.sessions.get(sid).is_some_and(|s| s.expires > now);
                match (m, parts.get(4).copied()) {
                    ("PUT", Some("request")) => {
                        let s = st
                            .sessions
                            .get_mut(sid)
                            .filter(|s| live && s.request.is_none());
                        match s {
                            Some(s) => {
                                s.request = Some(body);
                                Ok(Response {
                                    status: 204,
                                    body: Vec::new(),
                                })
                            }
                            None => res(409, json!({})),
                        }
                    }
                    ("GET", Some("result")) => {
                        if live && st.sessions[sid].response.is_some() {
                            let s = st
                                .sessions
                                .remove(sid)
                                .map(|s| s.response.unwrap_or(Value::Null));
                            res(200, s.unwrap_or(Value::Null))
                        } else {
                            res(202, json!({"status": "pending"}))
                        }
                    }
                    ("GET", None) => match st
                        .sessions
                        .get(sid)
                        .filter(|s| live && Some(&s.created_by) == device.as_ref())
                    {
                        None => res(404, json!({})),
                        Some(s) => match &s.request {
                            Some(q) => res(200, q.clone()),
                            None => res(202, json!({"status": "pending"})),
                        },
                    },
                    ("POST", Some("approve")) => {
                        let ready = st.sessions.get(sid).filter(|s| {
                            live && Some(&s.created_by) == device.as_ref() && s.response.is_none()
                        });
                        let Some(q) = ready.and_then(|s| s.request.clone()) else {
                            return res(409, json!({}));
                        };
                        let (Some(id), Some(pk)) = (q["device_id"].as_str(), key32(&q["pubkey"]))
                        else {
                            return res(409, json!({}));
                        };
                        if st.devices.contains_key(id) {
                            return res(409, json!({}));
                        }
                        st.devices.insert(id.to_owned(), Dev::new(pk, now));
                        if let Some(s) = st.sessions.get_mut(sid) {
                            s.response = Some(json!({"ct": body["ct"]}));
                        }
                        res(200, json!({"ok": true}))
                    }
                    _ => res(404, json!({})),
                }
            }
            _ => res(404, json!({})),
        }
    }
}
