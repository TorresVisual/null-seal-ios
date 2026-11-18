//! Unlock without the master password through a key only this device can produce, such as a
//! Windows Hello signature (#76, ADR 0001 "device wrapper").
//!
//! The Account Key is wrapped a second time under that key and the wrapper stays in this device's
//! local metadata: it is never synced and never part of an enrollment bundle. The key itself is
//! never stored here; the platform layer re-derives it for every unlock, so the wrapper is
//! useless without it. The master and recovery wrappers are untouched, so losing the device key
//! (Hello re-enrolled, TPM cleared) only means typing the master password again.

use super::*;

impl Account {
    /// Whether this device holds a device wrapper.
    pub fn device_unlock_enabled(&self) -> bool {
        self.meta.device_wrapper.is_some()
    }

    /// Wrap the Account Key under `key`. Needs the account unlocked (the Account Key is in
    /// memory); replaces an earlier wrapper.
    pub fn enable_device_unlock(&mut self, key: &Key) -> Result<(), AccountError> {
        let wrapper = wrap_account_key(
            self.session.account_key()?,
            &Wrapper::Device {
                key,
                device_id: self.meta.device_id.as_bytes(),
            },
        )?;
        let mut meta = self.meta.clone();
        meta.device_wrapper = Some(b64(&wrapper));
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        Ok(())
    }

    /// Forget the device wrapper. Works locked, so a lost or broken device key can be dropped.
    pub fn disable_device_unlock(&mut self) -> Result<(), AccountError> {
        let mut meta = self.meta.clone();
        meta.device_wrapper = None;
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        Ok(())
    }

    /// Unlock with the device key. A wrong key counts as a failed attempt, like a wrong password.
    pub fn unlock_with_device_key(&mut self, key: &Key, now_ms: u64) -> Result<(), AccountError> {
        let blob = unb64(
            self.meta
                .device_wrapper
                .as_deref()
                .ok_or(AccountError::NoDeviceUnlock)?,
        )?;
        let vaults = vault_entries(&self.meta.shared)?;
        self.session.unlock(
            now_ms,
            &self.store,
            &Wrapper::Device {
                key,
                device_id: self.meta.device_id.as_bytes(),
            },
            &blob,
            &vaults,
        )?;
        self.load_device()
    }
}

#[cfg(test)]
mod tests;
