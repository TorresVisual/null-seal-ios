//! Item version history and restore (#41). Versions live inside the item's own encrypted
//! payload (see `core_vault::merge`), so they sync, merge and re-encrypt with the item.

use super::*;

/// A prior version of a login, for the history view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoginVersion {
    /// Identifies the version; pass it to [`Account::restore_version`].
    pub at: String,
    pub fields: LoginFields,
}

impl Account {
    /// Prior versions of a live item, newest first.
    pub fn item_history(&self, id: &str) -> Result<Vec<LoginVersion>, AccountError> {
        let p = self.session.open_record(&self.live(id)?)?;
        Ok(p.history
            .into_iter()
            .map(|v| LoginVersion {
                at: v.at,
                fields: login_fields(v.data),
            })
            .collect())
    }

    /// Make a prior version current again. The version being replaced goes into the history,
    /// so a restore can itself be undone.
    pub fn restore_version(&mut self, id: &str, at: &str, now_ms: u64) -> Result<(), AccountError> {
        let old = self.session.open_record(&self.live(id)?)?;
        let version = old
            .history
            .iter()
            .find(|v| v.at == at)
            .ok_or(AccountError::NotFound)?;
        let mut new = old.clone();
        new.data = Item {
            created_at: old.data.created_at,
            updated_at: now_ms,
            deleted_at: old.data.deleted_at,
            ..version.data.clone()
        };
        self.write(id, Some(&old), Some(new), now_ms)
    }
}

#[cfg(test)]
mod tests;
