//! Bitwarden import (#67, #68): [`core_import`] parses, this writes.
//!
//! Each Bitwarden item gets a record id derived from its Bitwarden id, so importing the same export
//! again finds the records it wrote before and leaves them alone (an item the user has since edited
//! or deleted is not overwritten or resurrected).

use super::*;
use core_import::{
    Finding, Import, ImportError, bitwarden_csv, bitwarden_json, bitwarden_json_password,
};

/// What an import did. `report` names every field or item that did not map cleanly; it holds
/// paths and titles, never secret values.
pub struct ImportSummary {
    pub imported: usize,
    /// Items of this export already in the vault from an earlier import.
    pub already_present: usize,
    pub report: Vec<Finding>,
}

/// Record id of a Bitwarden item: first 16 bytes of a domain-separated SHA-256, as 32 hex chars.
fn record_id(source_id: &str) -> String {
    let h = sha256(&[b"null-seal/import/bitwarden/v1\0", source_id.as_bytes()].concat());
    h[..16].iter().map(|b| format!("{b:02x}")).collect()
}

impl Account {
    /// Import an unencrypted Bitwarden JSON export into the vault. The caller must tell the user the
    /// file is a plaintext copy of their secrets and should be deleted afterwards. A
    /// password-protected export is [`AccountError::ImportPasswordRequired`].
    pub fn import_bitwarden(
        &mut self,
        json: &[u8],
        now_ms: u64,
    ) -> Result<ImportSummary, AccountError> {
        self.session.account_key()?;
        self.write_import(bitwarden_json(json), now_ms)
    }

    /// Import a Bitwarden CSV export (logins and secure notes only).
    pub fn import_bitwarden_csv(
        &mut self,
        csv: &[u8],
        now_ms: u64,
    ) -> Result<ImportSummary, AccountError> {
        self.session.account_key()?;
        self.write_import(bitwarden_csv(csv), now_ms)
    }

    /// Import a password-protected Bitwarden JSON export. A wrong password writes nothing.
    pub fn import_bitwarden_password(
        &mut self,
        json: &[u8],
        password: &str,
        now_ms: u64,
    ) -> Result<ImportSummary, AccountError> {
        self.session.account_key()?;
        self.write_import(bitwarden_json_password(json, password), now_ms)
    }

    fn write_import(
        &mut self,
        parsed: Result<Import, ImportError>,
        now_ms: u64,
    ) -> Result<ImportSummary, AccountError> {
        let parsed = parsed.map_err(|e| match e {
            ImportError::Encrypted => AccountError::ImportEncrypted,
            ImportError::PasswordProtected => AccountError::ImportPasswordRequired,
            ImportError::WrongPassword => AccountError::ImportWrongPassword,
            ImportError::Format => AccountError::Format,
        })?;
        let (mut imported, mut already_present) = (0, 0);
        for item in parsed.items {
            let id = record_id(&item.source_id);
            if self.store.get(&id)?.is_some() {
                already_present += 1;
                continue;
            }
            self.write(&id, None, Some(item.payload), now_ms)?;
            imported += 1;
        }
        Ok(ImportSummary {
            imported,
            already_present,
            report: parsed.report,
        })
    }
}

#[cfg(test)]
mod tests;
