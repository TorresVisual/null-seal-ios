//! Bitwarden CSV export (#69). Carries logins and secure notes only; every other column and the
//! multi-line `fields` cell are kept verbatim in `extras["bitwarden"]` like the JSON importer does.
//!
//! The CSV has no item ids, so `source_id` is a hash of the row: re-importing the same file is
//! idempotent, and an identical duplicate row is reported instead of imported twice.

use crate::{Ctx, Import, ImportError, Imported, MAX_INPUT, Outcome, finding};
use core_crypto::sha256;
use core_vault::{Item, ItemType, Payload, Url};
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Parse a Bitwarden CSV export. Columns are found by header name, so their order does not matter.
pub fn bitwarden_csv(input: &[u8]) -> Result<Import, ImportError> {
    if input.len() > MAX_INPUT {
        return Err(ImportError::Format);
    }
    let text = std::str::from_utf8(input).map_err(|_| ImportError::Format)?;
    let mut rows = records(text.strip_prefix('\u{feff}').unwrap_or(text))
        .ok_or(ImportError::Format)?
        .into_iter();
    let header = rows.next().ok_or(ImportError::Format)?;
    let col = |name: &str| header.iter().position(|h| h == name);
    let (Some(c_type), Some(c_name)) = (col("type"), col("name")) else {
        return Err(ImportError::Format);
    };
    // Columns mapped below; anything else is kept per row.
    let known = [
        "folder",
        "favorite",
        "type",
        "name",
        "notes",
        "fields",
        "reprompt",
        "login_uri",
        "login_username",
        "login_password",
        "login_totp",
    ];

    let (mut items, mut report, mut seen) = (Vec::new(), Vec::new(), HashSet::new());
    for (n, row) in rows.enumerate() {
        let n = n + 1;
        if row.len() != header.len() {
            report.push(finding("", "", &format!("row[{n}]"), Outcome::Skipped));
            continue;
        }
        let get = |name: &str| col(name).map(|i| row[i].as_str()).unwrap_or_default();
        let name = row[c_name].clone();
        let id = row_id(&row);
        if !seen.insert(id.clone()) {
            report.push(finding(&id, &name, "row (duplicate)", Outcome::Skipped));
            continue;
        }
        let ty = match row[c_type].as_str() {
            "login" => ItemType::Login,
            "note" => ItemType::Note,
            t => {
                let path = if t.is_empty() {
                    "type".into()
                } else {
                    format!("type={t}")
                };
                report.push(finding(&id, &name, &path, Outcome::Skipped));
                continue;
            }
        };

        let some = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        let it = Item {
            title: name.clone(),
            notes: some(get("notes")),
            favorite: get("favorite") == "1",
            reprompt: get("reprompt") == "1",
            folder: some(get("folder")),
            username: some(get("login_username")),
            password: some(get("login_password")),
            totp: some(get("login_totp")),
            urls: get("login_uri")
                .lines()
                .filter(|u| !u.is_empty())
                .map(|url| Url {
                    url: url.to_owned(),
                    ..Url::default()
                })
                .collect(),
            ..Item::default()
        };
        let mut c = Ctx {
            id: id.clone(),
            name: name.clone(),
            bw: Map::new(),
            report: &mut report,
        };
        if let Some(f) = some(get("fields")) {
            c.keep("fields", Value::String(f));
        }
        for (h, v) in header.iter().zip(&row) {
            if !known.contains(&h.as_str()) && !v.is_empty() {
                c.keep(h, Value::String(v.clone()));
            }
        }
        let bw = c.bw;
        let mut payload = Payload::new(ty, it);
        payload
            .extras
            .insert("bitwarden".to_owned(), Value::Object(bw));
        items.push(Imported {
            source_id: id,
            payload,
        });
    }
    Ok(Import { items, report })
}

/// `csv:` + hex of the first 16 bytes of SHA-256 over the row's cells.
fn row_id(row: &[String]) -> String {
    let h = sha256(row.join("\0").as_bytes());
    h[..16]
        .iter()
        .fold("csv:".to_owned(), |s, b| s + &format!("{b:02x}"))
}

/// RFC 4180: a quoted cell may hold commas, `""` and line breaks; LF or CRLF ends a record.
/// `None` if a quote is never closed. Blank lines are not records.
fn records(s: &str) -> Option<Vec<Vec<String>>> {
    let (mut rows, mut row, mut cell) = (Vec::new(), Vec::new(), String::new());
    let (mut quoted, mut it) = (false, s.chars().peekable());
    while let Some(c) = it.next() {
        match (c, quoted) {
            ('"', true) if it.peek() == Some(&'"') => {
                cell.push('"');
                it.next();
            }
            ('"', true) => quoted = false,
            ('"', false) if cell.is_empty() => quoted = true,
            (',', false) => row.push(std::mem::take(&mut cell)),
            ('\r', false) if it.peek() == Some(&'\n') => {}
            ('\n', false) => {
                row.push(std::mem::take(&mut cell));
                rows.push(std::mem::take(&mut row));
            }
            _ => cell.push(c),
        }
    }
    if quoted {
        return None;
    }
    if !cell.is_empty() || !row.is_empty() {
        row.push(cell);
        rows.push(row);
    }
    rows.retain(|r| r.as_slice() != [""]);
    Some(rows)
}
