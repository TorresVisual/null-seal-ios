//! Master password change and KDF upgrade (#45, ADR 0001 "Operations").
//!
//! Only the master wrapper of the Account Key is replaced (fresh salt, new password, KDF
//! parameters); the Account Key, Vault Keys and records are untouched, so nothing re-syncs.

use super::*;

impl Account {
    /// Replace the master password and/or raise the Argon2id cost. Needs the account unlocked
    /// and the current password (re-authentication). `params` must not lower memory or passes.
    /// The new wrapper is written in one store update; on any error nothing has changed.
    pub fn change_password(
        &mut self,
        old: &str,
        new: &str,
        params: KdfParams,
    ) -> Result<(), AccountError> {
        let ak = self.session.account_key()?;
        let cur = header_of(&self.meta.shared)?;
        self.check_master_password(old)?;
        check_password(new)?;
        if params.m_kib() < cur.params.m_kib() || params.t() < cur.params.t() {
            return Err(AccountError::Format);
        }

        let header = MasterHeader::new(params)?;
        let mut meta = self.meta.clone();
        meta.shared.kdf = [params.m_kib(), params.t(), params.p()];
        meta.shared.salt = b64(&header.salt);
        meta.shared.pw_norm = header.pw_norm;
        meta.shared.master_wrapper = b64(&wrap_account_key(
            ak,
            &Wrapper::Master {
                password: new,
                header: &header,
            },
        )?);
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        Ok(())
    }

    /// Set a new master password with the recovery code, for an account that has none (restored
    /// from a relay backup, #47) or whose password is forgotten. Rotates the recovery key too
    /// and returns the new code to show once; the Account Key, Vault Keys and records are
    /// untouched. Works on a locked account. Nothing changes unless every step succeeds.
    pub fn reset_master_password(
        &mut self,
        code: &str,
        new: &str,
        params: KdfParams,
    ) -> Result<Zeroizing<String>, AccountError> {
        check_password(new)?;
        let recovery = unb64(&self.meta.shared.recovery_wrapper)?;
        let r =
            core_keys::restore(&recovery, code, new, params).map_err(|_| AccountError::Crypto)?;
        let mut meta = self.meta.clone();
        meta.shared.kdf = [
            r.master_header.params.m_kib(),
            r.master_header.params.t(),
            r.master_header.params.p(),
        ];
        meta.shared.salt = b64(&r.master_header.salt);
        meta.shared.pw_norm = r.master_header.pw_norm;
        meta.shared.master_wrapper = b64(&r.master_wrapper);
        meta.shared.recovery_wrapper = b64(&r.recovery_wrapper);
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        self.lock();
        Ok(r.recovery_code)
    }
}

#[cfg(test)]
mod tests;
