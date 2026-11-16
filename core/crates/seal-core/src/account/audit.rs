//! Weak and reused passwords of the active vault (#70). Computed in memory from the decrypted
//! logins and returned as ids and names only: no password leaves this function, and nothing here
//! touches the network.

use super::*;
use std::collections::HashMap;

/// A login named in the report: never contains a secret.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AuditItem {
    pub id: String,
    pub title: String,
    pub username: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Audit {
    /// Logins with a password: the denominator for the dashboard score.
    pub total: usize,
    /// Logins whose password scores below 3 (zxcvbn).
    pub weak: Vec<AuditItem>,
    /// Groups of two or more logins sharing one password.
    pub reused: Vec<Vec<AuditItem>>,
}

/// A login password prepared for the breach check (#71): the item to name if it is breached and
/// the password's SHA-1 as 40 upper-case hex characters, which never leaves the process whole.
pub struct BreachProbe {
    item: AuditItem,
    sha1: Zeroizing<String>,
}

impl Account {
    /// Calls `f` for every login of the active vault that has a password. Locked is an error, not
    /// an empty walk; records this build cannot open are skipped.
    fn each_login_password(
        &self,
        mut f: impl FnMut(AuditItem, Zeroizing<String>),
    ) -> Result<(), AccountError> {
        let vault = self.vault_id()?;
        self.session.account_key()?;
        for rec in self.store.list(vault)?.iter().filter(|r| !r.tombstone) {
            let Ok(p) = self.session.open_record(rec) else {
                continue;
            };
            if p.item_type != ItemType::Login {
                continue;
            }
            let d = p.data;
            let Some(pw) = d.password.map(Zeroizing::new).filter(|p| !p.is_empty()) else {
                continue;
            };
            let item = AuditItem {
                id: rec.id.clone(),
                title: d.title,
                username: d.username.unwrap_or_default(),
            };
            f(item, pw);
        }
        Ok(())
    }

    /// Weak and reused passwords across the logins of the active vault.
    pub fn audit_logins(&self) -> Result<Audit, AccountError> {
        let mut audit = Audit::default();
        // Keyed by digest so no second copy of a password sits in a map.
        let mut by_pw: HashMap<[u8; 32], Vec<AuditItem>> = HashMap::new();
        self.each_login_password(|item, pw| {
            audit.total += 1;
            if core_gen::estimate(&pw, &[&item.username, &item.title]).score < 3 {
                audit.weak.push(item.clone());
            }
            by_pw.entry(sha256(pw.as_bytes())).or_default().push(item);
        })?;
        audit.reused = by_pw.into_values().filter(|g| g.len() > 1).collect();
        let key = |i: &AuditItem| (i.title.to_lowercase(), i.id.clone());
        audit.weak.sort_by_key(key);
        for g in &mut audit.reused {
            g.sort_by_key(key);
        }
        audit.reused.sort_by_key(|g| key(&g[0]));
        Ok(audit)
    }

    /// The first half of the breach check: hash every login password locally. Pass the result to
    /// [`check_breaches`], which can run without holding the account.
    pub fn breach_probes(&self) -> Result<Vec<BreachProbe>, AccountError> {
        use core::fmt::Write;
        let mut probes = Vec::new();
        self.each_login_password(|item, pw| {
            let mut sha1 = Zeroizing::new(String::with_capacity(40));
            for b in core_crypto::sha1(pw.as_bytes()) {
                let _ = write!(sha1, "{b:02X}");
            }
            probes.push(BreachProbe { item, sha1 });
        })?;
        Ok(probes)
    }
}

/// Pwned Passwords k-anonymity check (#71). `fetch` gets only the first 5 hex characters of a
/// SHA-1 and returns the range body (`SUFFIX:COUNT` lines); the suffix is matched here, so the
/// rest of a hash is never sent. One request per distinct prefix. Padding entries (count 0) do not
/// count as breached. Any fetch error aborts the check with no partial report.
pub fn check_breaches(
    probes: Vec<BreachProbe>,
    mut fetch: impl FnMut(&str) -> Result<String, String>,
) -> Result<Vec<AuditItem>, String> {
    let mut ranges: HashMap<String, String> = HashMap::new();
    let mut hits = Vec::new();
    for BreachProbe { item, sha1 } in probes {
        let (prefix, suffix) = sha1.split_at(5);
        if !ranges.contains_key(prefix) {
            ranges.insert(prefix.to_owned(), fetch(prefix)?);
        }
        let breached = ranges[prefix].lines().any(|l| {
            l.split_once(':').is_some_and(|(s, n)| {
                s.trim().eq_ignore_ascii_case(suffix)
                    && n.trim().parse::<u64>().is_ok_and(|n| n > 0)
            })
        });
        if breached {
            hits.push(item);
        }
    }
    hits.sort_by_key(|i| (i.title.to_lowercase(), i.id.clone()));
    Ok(hits)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn finds_planted_weak_and_reused_passwords_and_nothing_else() {
        let (mut setup, code) = begin_setup(
            Store::open_in_memory().unwrap(),
            "correct horse battery staple 42!",
            KdfParams::new(19 * 1024, 2, 1).unwrap(),
        )
        .unwrap();
        let mut a = setup.confirm(&code, 1).unwrap();
        let strong = "k3#Vq9!zLm2@pXw7&Rt5";
        let mut add = |title: &str, pw: &str, at: u64| {
            let f = LoginFields {
                title: title.into(),
                username: "me".into(),
                password: pw.into(),
                url: String::new(),
                notes: String::new(),
            };
            a.save_login(None, &f, at).unwrap()
        };
        let weak = add("Forum", "password1", 2);
        let r1 = add("Shop", strong, 3);
        let r2 = add("Bank", strong, 4);
        add("Mail", "Zq8$nT4%vB1^hJ6*cD3(", 5);
        add("Empty", "", 6);

        let r = a.audit_logins().unwrap();
        let ids = |v: &[AuditItem]| v.iter().map(|i| i.id.clone()).collect::<Vec<_>>();
        assert_eq!(r.total, 4); // Empty has no password
        assert_eq!(ids(&r.weak), [weak]);
        assert_eq!(r.reused.len(), 1);
        assert_eq!(ids(&r.reused[0]), [r2, r1]); // Bank before Shop
        assert!(!format!("{r:?}").contains(strong));

        a.lock();
        assert!(a.audit_logins().is_err());
    }

    #[test]
    fn breach_check_sends_only_prefixes_flags_known_and_fails_cleanly() {
        let (mut setup, code) = begin_setup(
            Store::open_in_memory().unwrap(),
            "correct horse battery staple 42!",
            KdfParams::new(19 * 1024, 2, 1).unwrap(),
        )
        .unwrap();
        let mut a = setup.confirm(&code, 1).unwrap();
        let mut add = |title: &str, pw: &str, at: u64| {
            let f = LoginFields {
                title: title.into(),
                username: "me".into(),
                password: pw.into(),
                url: String::new(),
                notes: String::new(),
            };
            a.save_login(None, &f, at).unwrap()
        };
        let bad = add("Forum", "password", 2);
        add("Shop", "k3#Vq9!zLm2@pXw7&Rt5", 3);
        let same = add("Dup", "password", 4);
        add("Empty", "", 5);

        // "password" is a known breached password; its real SHA-1 is 5BAA6 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
        let known = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";
        let mut sent = Vec::new();
        let hits = check_breaches(a.breach_probes().unwrap(), |p| {
            sent.push(p.to_owned());
            // padded: a real hit, a zero-count padding row, and noise
            let pad = "A".repeat(35);
            Ok(format!(
                "{known}:9545824
{pad}:0
0018A45C4D1DEF81644B54AB7F969B88D65:3"
            ))
        })
        .unwrap();
        let ids: Vec<_> = hits.iter().map(|i| i.id.clone()).collect();
        assert_eq!(ids, [same, bad]); // Dup before Forum
        assert!(sent.iter().all(|p| p.len() == 5), "{sent:?}");
        assert!(sent.contains(&"5BAA6".to_owned()));
        assert_eq!(sent.len(), 2); // "password" asked once, the strong one once

        // a zero count (padding) is not a hit
        let zero = a.breach_probes().unwrap();
        let none = check_breaches(zero, |_| Ok(format!("{known}:0"))).unwrap();
        assert!(none.is_empty());

        // offline: an error, no partial report
        let err = check_breaches(a.breach_probes().unwrap(), |_| Err("offline".into()));
        assert_eq!(err.unwrap_err(), "offline");
        a.lock();
        assert!(a.breach_probes().is_err());
    }
}
