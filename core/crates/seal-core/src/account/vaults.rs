//! Several vaults in one account (#64). Each vault has its own random Vault Key, wrapped by the
//! Account Key; the account locks as a whole. One vault is active at a time and every item
//! command, the search and autofill see only that one. The active vault is in-memory state: it
//! resets to the first vault on every lock.
//!
//! A vault created here reaches the other devices through the attestation each device keeps on
//! the relay (sealed under the Account Key, see `rotate.rs`): at its next sync a device lists the
//! attestations, adopts vaults it lacks, and only then pulls (#130). Records of a vault it has
//! not heard of yet defer the pull instead of being dropped.

use super::*;

const MAX_NAME_CHARS: usize = 64;
/// Shown for the vault created at setup, which has no name of its own.
const FIRST_NAME: &str = "Personal";

/// A vault as the selector shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VaultInfo {
    pub id: String,
    pub name: String,
    pub active: bool,
}

fn name_ctx(vault_id: &str) -> Vec<u8> {
    context(&[b"vault-name", vault_id.as_bytes()])
}

/// Seal a vault name under the Account Key of generation `ak_gen`; empty stays empty.
pub(super) fn seal_name(
    ak: &Key,
    ak_gen: u32,
    vault_id: &str,
    name: &str,
) -> Result<String, AccountError> {
    if name.is_empty() {
        return Ok(String::new());
    }
    Ok(b64(&seal(
        ak,
        ak_gen,
        &name_ctx(vault_id),
        name.as_bytes(),
    )?))
}

pub(super) fn open_name(ak: &Key, v: &VaultMeta) -> Result<String, AccountError> {
    if v.name.is_empty() {
        return Ok(String::new());
    }
    let (_, pt) = open(ak, &name_ctx(&v.id), &unb64(&v.name)?).map_err(|_| AccountError::Crypto)?;
    String::from_utf8(pt.to_vec()).map_err(|_| AccountError::Format)
}

impl Account {
    /// Every vault with its name; `active` marks the one the item commands act on.
    pub fn list_vaults(&self) -> Result<Vec<VaultInfo>, AccountError> {
        let ak = self.session.account_key()?;
        let active = self.vault_id()?;
        self.meta
            .shared
            .vaults
            .iter()
            .map(|v| {
                let name = open_name(ak, v)?;
                Ok(VaultInfo {
                    id: v.id.clone(),
                    name: if name.is_empty() {
                        FIRST_NAME.into()
                    } else {
                        name
                    },
                    active: v.id == active,
                })
            })
            .collect()
    }

    /// Make `id` the active vault.
    pub fn select_vault(&mut self, id: &str) -> Result<(), AccountError> {
        self.session.account_key()?;
        if !self.meta.shared.vaults.iter().any(|v| v.id == id) {
            return Err(AccountError::NotFound);
        }
        self.active = Some(id.to_owned());
        Ok(())
    }

    /// Create an empty vault under its own fresh key and make it the active one.
    pub fn create_vault(&mut self, name: &str) -> Result<String, AccountError> {
        let name = name.trim();
        if name.is_empty() || name.chars().count() > MAX_NAME_CHARS {
            return Err(AccountError::Format);
        }
        let id = random_id()?;
        let ak_gen = self.meta.shared.ak_gen;
        let (wrapped, sealed_name) = {
            let ak = self.session.account_key()?;
            let vk = new_vault_key()?;
            (
                wrap_vault_key(ak, ak_gen, id.as_bytes(), 0, &vk)?,
                seal_name(ak, ak_gen, &id, name)?,
            )
        };
        let mut meta = self.meta.clone();
        meta.shared.vaults.push(VaultMeta {
            id: id.clone(),
            key_gen: 0,
            wrapped_key: b64(&wrapped),
            old: Vec::new(),
            name: sealed_name,
        });
        save_meta(&self.store, &meta)?;
        self.meta = meta;
        let entry = VaultEntry {
            id: id.clone(),
            key_gen: 0,
            wrapped_key: wrapped,
            old: Vec::new(),
        };
        if let Err(e) = self.session.add_vault(&self.store, &entry) {
            // disk has the vault, memory does not: lock so the next unlock reads the disk
            self.lock();
            return Err(e.into());
        }
        self.active = Some(id.clone());
        Ok(id)
    }

    /// Move an item of the active vault to `target`: it is re-encrypted under the target's key
    /// and gets a new id there (the relay pins an id to its vault), and the original is deleted.
    /// The copy is written first, so an interruption leaves a duplicate, never a loss.
    pub fn move_item(
        &mut self,
        id: &str,
        target: &str,
        now_ms: u64,
    ) -> Result<String, AccountError> {
        let src = self.live(id)?;
        if src.vault == target || !self.meta.shared.vaults.iter().any(|v| v.id == target) {
            return Err(AccountError::NotFound);
        }
        let payload = self.session.open_record(&src)?;
        let new_id = random_id()?;
        self.write_in(target, &new_id, None, Some(payload), now_ms)?;
        self.write_in(&src.vault, id, None, None, now_ms)?;
        Ok(new_id)
    }
}

#[cfg(test)]
mod tests;
