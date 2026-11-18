//! Bitwarden unencrypted-JSON import (#67; field mapping from spike #12).
//!
//! Zero silent loss: every key that does not map to an [`Item`] field is kept verbatim under
//! `extras["bitwarden"]` and listed in the report as [`Outcome::Preserved`]. Card, identity, SSH
//! key and newer Bitwarden types have no item type here yet: they import as secure notes whose
//! original object stays in `extras` (#69). Only an unknown type is [`Outcome::Skipped`].
//! Findings carry paths, never values (no secrets in reports or logs).
//!
//! Pure: no I/O. The only crypto is opening a password-protected export (#68), via `core-crypto`.
//! The caller writes [`Imported`] items under ids derived from `source_id`, which makes a
//! re-import idempotent.

mod csv;
mod encrypted;
pub use csv::bitwarden_csv;
pub use encrypted::bitwarden_json_password;

use core_vault::{Item, ItemType, Payload, Url};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashSet};

/// Bitwarden `UriMatchType` 0..=5; `null` (use the app default) is `None`, not `domain`.
const MATCH: [&str; 6] = ["domain", "host", "starts_with", "exact", "regex", "never"];

#[derive(Debug, PartialEq, Eq)]
pub enum ImportError {
    /// Not a Bitwarden JSON export.
    Format,
    /// Account-encrypted export: only that Bitwarden account can read it.
    Encrypted,
    /// Password-protected export: ask for the password, then [`bitwarden_json_password`].
    PasswordProtected,
    /// [`bitwarden_json_password`] was given the wrong password.
    WrongPassword,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Kept verbatim in the item's `extras`, not usable yet (custom fields, passkeys, ...).
    Preserved,
    /// Not imported.
    Skipped,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Source (Bitwarden) id of the item; empty for findings on the export itself.
    pub id: String,
    pub name: String,
    pub path: String,
    pub outcome: Outcome,
}

#[derive(Debug, Serialize)]
pub struct Imported {
    pub source_id: String,
    pub payload: Payload,
}

#[derive(Debug, Serialize)]
pub struct Import {
    pub items: Vec<Imported>,
    pub report: Vec<Finding>,
}

/// Largest export accepted (SR-23): the parsed tree and the imported payloads are several times
/// the file size in memory.
pub const MAX_INPUT: usize = 64 * 1024 * 1024;

/// Parse a Bitwarden unencrypted JSON export (individual or organization shape).
pub fn bitwarden_json(input: &[u8]) -> Result<Import, ImportError> {
    if input.len() > MAX_INPUT {
        return Err(ImportError::Format);
    }
    let Value::Object(mut root) = serde_json::from_slice(input).map_err(|_| ImportError::Format)?
    else {
        return Err(ImportError::Format);
    };
    match root.remove("encrypted") {
        Some(Value::Bool(true)) => {
            return Err(match root.get("passwordProtected") {
                Some(Value::Bool(true)) => ImportError::PasswordProtected,
                _ => ImportError::Encrypted,
            });
        }
        None | Some(Value::Bool(false)) => {}
        Some(_) => return Err(ImportError::Format),
    }
    let Some(Value::Array(items)) = root.remove("items") else {
        return Err(ImportError::Format);
    };
    let mut report = Vec::new();
    let folders = names(root.remove("folders"), "folders", &mut report);
    let colls = names(root.remove("collections"), "collections", &mut report);
    for key in root.keys() {
        report.push(finding("", "(export)", key, Outcome::Skipped));
    }
    let mut seen = HashSet::new();
    let mut used = HashSet::new();
    let items = items
        .into_iter()
        .filter_map(|raw| item(raw, &folders, &colls, (&mut seen, &mut used), &mut report))
        .collect();
    // A folder or collection no imported item uses has nowhere to live in the vault.
    for (what, list) in [("folders", &folders), ("collections", &colls)] {
        for id in list.keys().filter(|id| !used.contains(*id)) {
            let path = format!("{what}[{id}] (unused)");
            report.push(finding("", "(export)", &path, Outcome::Skipped));
        }
    }
    Ok(Import { items, report })
}

fn finding(id: &str, name: &str, path: &str, outcome: Outcome) -> Finding {
    Finding {
        id: id.to_owned(),
        name: name.to_owned(),
        path: path.to_owned(),
        outcome,
    }
}

/// `[{id, name, ...}]` -> id to name. Extra keys of a folder/collection (`organizationId`,
/// `externalId`) are reported as skipped: they have no home in the vault.
fn names(v: Option<Value>, what: &str, report: &mut Vec<Finding>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(Value::Array(list)) = v else {
        return out;
    };
    for (i, e) in list.into_iter().enumerate() {
        let p = format!("{what}[{i}]");
        let Value::Object(mut m) = e else {
            report.push(finding("", "(export)", &p, Outcome::Skipped));
            continue;
        };
        let id = m.remove("id");
        let name = m.remove("name");
        match (
            id.as_ref().and_then(Value::as_str),
            name.as_ref().and_then(Value::as_str),
        ) {
            (Some(id), Some(name)) => {
                if out.insert(id.to_owned(), name.to_owned()).is_some() {
                    report.push(finding(
                        "",
                        "(export)",
                        &format!("{p} (duplicate id)"),
                        Outcome::Skipped,
                    ));
                }
            }
            _ => report.push(finding("", "(export)", &p, Outcome::Skipped)),
        }
        for k in m.keys() {
            report.push(finding(
                "",
                "(export)",
                &format!("{p}.{k}"),
                Outcome::Skipped,
            ));
        }
    }
    out
}

/// One item under construction: collects `extras["bitwarden"]` and its findings.
struct Ctx<'a> {
    id: String,
    name: String,
    bw: Map<String, Value>,
    report: &'a mut Vec<Finding>,
}

impl Ctx<'_> {
    fn keep(&mut self, path: &str, v: Value) {
        self.bw.insert(path.to_owned(), v);
        self.report
            .push(finding(&self.id, &self.name, path, Outcome::Preserved));
    }

    /// Remove `key`; a non-null value `f` cannot read is preserved instead of lost.
    fn get<T>(
        &mut self,
        m: &mut Map<String, Value>,
        key: &str,
        path: &str,
        f: impl Fn(&Value) -> Option<T>,
    ) -> Option<T> {
        match m.remove(key) {
            None | Some(Value::Null) => None,
            Some(v) => {
                let r = f(&v);
                if r.is_none() {
                    self.keep(path, v);
                }
                r
            }
        }
    }

    /// A string; empty counts as absent.
    fn text(&mut self, m: &mut Map<String, Value>, key: &str, path: &str) -> Option<String> {
        self.get(m, key, path, |v| v.as_str().map(str::to_owned))
            .filter(|s| !s.is_empty())
    }

    fn date(&mut self, m: &mut Map<String, Value>, key: &str) -> Option<u64> {
        self.get(m, key, key, |v| v.as_str().and_then(parse_ms))
    }

    /// Keep a value no struct models, unless it is empty.
    fn stash(&mut self, m: &mut Map<String, Value>, key: &str, path: &str) {
        match m.remove(key) {
            None | Some(Value::Null) => {}
            Some(Value::Array(a)) if a.is_empty() => {}
            Some(v) => self.keep(path, v),
        }
    }

    /// Everything left in `m` is preserved.
    fn rest(&mut self, m: Map<String, Value>, prefix: &str) {
        for (k, v) in m {
            self.keep(&format!("{prefix}{k}"), v);
        }
    }

    fn login(&mut self, it: &mut Item, v: Value) {
        let Value::Object(mut m) = v else {
            return self.keep("login", v);
        };
        it.username = self.text(&mut m, "username", "login.username");
        it.password = self.text(&mut m, "password", "login.password");
        it.totp = self.text(&mut m, "totp", "login.totp");
        match m.remove("uris") {
            Some(Value::Array(uris)) => {
                for (i, u) in uris.into_iter().enumerate() {
                    self.uri(it, i, u);
                }
            }
            None | Some(Value::Null) => {}
            Some(v) => self.keep("login.uris", v),
        }
        self.rest(m, "login.");
    }

    fn uri(&mut self, it: &mut Item, i: usize, u: Value) {
        let p = format!("login.uris[{i}]");
        let Value::Object(mut m) = u else {
            return self.keep(&p, u);
        };
        let url = self.text(&mut m, "uri", &format!("{p}.uri"));
        let mode = m
            .get("match")
            .and_then(Value::as_u64)
            .and_then(|n| MATCH.get(usize::try_from(n).ok()?))
            .copied();
        // An unknown mode stays in `m` and survives as an unknown key of the URL.
        if mode.is_some() || m.get("match").is_some_and(Value::is_null) {
            m.remove("match");
        }
        let Some(url) = url else {
            if mode.is_some() || !m.is_empty() {
                self.report
                    .push(finding(&self.id, &self.name, &p, Outcome::Skipped));
            }
            return;
        };
        for k in m.keys() {
            let path = format!("{p}.{k}");
            self.report
                .push(finding(&self.id, &self.name, &path, Outcome::Preserved));
        }
        it.urls.push(Url {
            url,
            r#match: mode.map(str::to_owned),
            unknown: m,
        });
    }
}

fn item(
    raw: Value,
    folders: &BTreeMap<String, String>,
    colls: &BTreeMap<String, String>,
    (seen, used): (&mut HashSet<String>, &mut HashSet<String>),
    report: &mut Vec<Finding>,
) -> Option<Imported> {
    let Value::Object(mut m) = raw else {
        report.push(finding("", "", "item", Outcome::Skipped));
        return None;
    };
    let name = match m.remove("name") {
        Some(Value::String(s)) => s,
        None | Some(Value::Null) => String::new(),
        // Not a string: keep it below (after `c` exists) instead of losing it.
        Some(v) => {
            m.insert("name".to_owned(), v);
            String::new()
        }
    };
    let id = m
        .remove("id")
        .and_then(|v| v.as_str().map(str::to_owned))
        .filter(|s| !s.is_empty());
    let Some(id) = id else {
        report.push(finding("", &name, "id", Outcome::Skipped));
        return None;
    };
    if !seen.insert(id.clone()) {
        report.push(finding(&id, &name, "id (duplicate)", Outcome::Skipped));
        return None;
    }
    let mut downgraded = None;
    let ty = match m.remove("type").as_ref().and_then(Value::as_u64) {
        Some(1) => ItemType::Login,
        Some(2) => ItemType::Note,
        // Card, identity, SSH key, bank account, driver's license, passport: kept as a note.
        Some(t @ 3..=8) => {
            downgraded = Some(t);
            ItemType::Note
        }
        t => {
            let path = t.map_or("type".to_owned(), |t| format!("type={t}"));
            report.push(finding(&id, &name, &path, Outcome::Skipped));
            return None;
        }
    };

    let mut c = Ctx {
        id: id.clone(),
        name: name.clone(),
        bw: Map::new(),
        report,
    };
    c.bw.insert("id".to_owned(), Value::String(id.clone()));
    if let Some(t) = downgraded {
        c.keep("type", json!(t));
    }
    let mut it = Item {
        title: name,
        ..Item::default()
    };
    it.notes = c.text(&mut m, "notes", "notes");
    it.favorite = c
        .get(&mut m, "favorite", "favorite", Value::as_bool)
        .unwrap_or(false);
    it.reprompt = c
        .get(&mut m, "reprompt", "reprompt", Value::as_u64)
        .is_some_and(|n| n != 0);
    it.created_at = c.date(&mut m, "creationDate").unwrap_or(0);
    it.updated_at = c.date(&mut m, "revisionDate").unwrap_or(0);
    it.deleted_at = c.date(&mut m, "deletedDate");

    if let Some(fid) = c.text(&mut m, "folderId", "folderId") {
        match folders.get(&fid) {
            Some(name) => {
                used.insert(fid);
                it.folder = Some(name.clone());
            }
            None => c.keep("folderId", Value::String(fid)),
        }
    }
    if let Some(org) = c.text(&mut m, "organizationId", "organizationId") {
        c.keep("organizationId", Value::String(org));
    }
    let ids = c.get(&mut m, "collectionIds", "collectionIds", |v| {
        v.as_array().cloned()
    });
    let mut unresolved = Vec::new();
    for cid in ids.unwrap_or_default() {
        match cid.as_str().and_then(|s| colls.get(s)) {
            Some(name) => {
                it.tags.push(format!("collection:{name}"));
                used.extend(cid.as_str().map(str::to_owned));
            }
            None => unresolved.push(cid),
        }
    }
    if !unresolved.is_empty() {
        c.keep("collectionIds", Value::Array(unresolved));
    }

    for key in ["archivedDate", "fields", "passwordHistory"] {
        c.stash(&mut m, key, key);
    }
    match m.remove("secureNote") {
        None | Some(Value::Null) => {}
        Some(v) if v == json!({"type": 0}) => {}
        Some(v) => c.keep("secureNote", v),
    }
    if let Some(v) = m.remove("login").filter(|v| !v.is_null()) {
        c.login(&mut it, v);
    }
    c.rest(m, "");

    let mut payload = Payload::new_login(it);
    payload.item_type = ty;
    payload
        .extras
        .insert("bitwarden".to_owned(), Value::Object(c.bw));
    Some(Imported {
        source_id: id,
        payload,
    })
}

/// `YYYY-MM-DDTHH:MM:SS[.fff]Z` (what Bitwarden writes) to Unix milliseconds.
fn parse_ms(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    let sep_ok = b.len() >= 20
        && s.is_ascii()
        && [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')]
            .iter()
            .all(|&(i, c)| b[i] == c)
        && b[b.len() - 1] == b'Z';
    if !sep_ok {
        return None;
    }
    let num = |a: usize, z: usize| -> Option<i64> {
        let t = s.get(a..z)?;
        if !t.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        t.parse().ok()
    };
    let ms = match b.len() {
        20 => 0,
        _ if b[19] == b'.' && b.len() > 21 => {
            let digits = s.get(20..b.len() - 1)?;
            if !digits.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            format!("{digits:0<3}").get(..3)?.parse::<i64>().ok()?
        }
        _ => return None,
    };
    let (y, mo, d) = (num(0, 4)?, num(5, 7)?, num(8, 10)?);
    let (h, mi, sec) = (num(11, 13)?, num(14, 16)?, num(17, 19)?);
    if y < 1970
        || !(1..=12).contains(&mo)
        || !(1..=31).contains(&d)
        || h > 23
        || mi > 59
        || sec > 59
    {
        return None;
    }
    // Days since 1970-01-01 (Howard Hinnant's days_from_civil).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from((((days * 24 + h) * 60 + mi) * 60 + sec) * 1000 + ms).ok()
}

#[cfg(test)]
mod tests;
