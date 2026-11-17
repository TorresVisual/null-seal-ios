//! Full vault export (#48, SR-15).
//!
//! * **Encrypted export** is the encrypted backup file ([`Account::backup`], #46): every record of
//!   every type, opened only with the master password or recovery key, restorable on a clean
//!   profile. There is no second format to keep in sync.
//! * **Plaintext export** is readable JSON of every live item, for leaving Null Seal or for
//!   inspection. It is the one place secrets leave the vault unencrypted, so it re-authenticates
//!   with the master password (an unlocked laptop is not enough) and the caller must show the
//!   warning before asking. History, merge stamps and deleted items are not exported.
//!
//! [`Account::import_plaintext`] reads that JSON back. Items keep their ids, so importing into
//! the same vault updates in place instead of duplicating, and importing twice changes nothing.

use super::*;
use core_vault::SCHEMA_VERSION;

const FORMAT: &str = "null-seal-export";
const VERSION: u32 = 1;
/// Bound for an untrusted import file (SR-23).
const MAX_IMPORT: usize = 256 * 1024 * 1024;

#[derive(Serialize, Deserialize)]
struct Export {
    format: String,
    version: u32,
    exported_ms: u64,
    items: Vec<ExportItem>,
}

#[derive(Serialize, Deserialize)]
struct ExportItem {
    id: String,
    #[serde(flatten)]
    payload: Payload,
}

/// The plaintext export and what it covers. Wipe or encrypt the bytes as soon as they are written.
pub struct PlainExport {
    pub json: Zeroizing<Vec<u8>>,
    pub items: usize,
    /// Live items this build cannot read (written by a newer schema); they are not in `json`.
    pub skipped: usize,
}

impl Account {
    /// Plaintext JSON of every live item. Needs the account unlocked and the master password.
    pub fn export_plaintext(
        &self,
        password: &str,
        now_ms: u64,
    ) -> Result<PlainExport, AccountError> {
        self.session.account_key()?;
        self.check_master_password(password)?;
        let (mut items, mut skipped) = (Vec::new(), 0);
        for v in &self.meta.shared.vaults {
            for rec in self.store.list(&v.id)?.iter().filter(|r| !r.tombstone) {
                match self.session.open_record(rec) {
                    Ok(mut payload) => {
                        payload.fields_hlc.clear();
                        payload.history.clear();
                        items.push(ExportItem {
                            id: rec.id.clone(),
                            payload,
                        });
                    }
                    Err(_) => skipped += 1,
                }
            }
        }
        let count = items.len();
        let json = serde_json::to_vec_pretty(&Export {
            format: FORMAT.into(),
            version: VERSION,
            exported_ms: now_ms,
            items,
        })
        .map_err(|_| AccountError::Format)?;
        Ok(PlainExport {
            json: Zeroizing::new(json),
            items: count,
            skipped,
        })
    }

    /// Import a plaintext export. All of it is validated before anything is written. Returns the
    /// number of items created or updated.
    pub fn import_plaintext(&mut self, json: &[u8], now_ms: u64) -> Result<usize, AccountError> {
        self.session.account_key()?;
        if json.len() > MAX_IMPORT {
            return Err(AccountError::Format);
        }
        let export: Export = serde_json::from_slice(json).map_err(|_| AccountError::Format)?;
        if export.format != FORMAT
            || export.version != VERSION
            || export.items.iter().any(|i| {
                !(1..=80).contains(&i.id.len()) || // the relay refuses longer ids
                     !(1..=SCHEMA_VERSION).contains(&i.payload.v)
            })
        {
            return Err(AccountError::Format);
        }
        let count = export.items.len();
        for item in export.items {
            let old = self
                .live(&item.id)
                .ok()
                .map(|r| self.session.open_record(&r))
                .transpose()?;
            let mut payload = item.payload;
            payload.fields_hlc.clear();
            self.write(&item.id, old.as_ref(), Some(payload), now_ms)?;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests;
