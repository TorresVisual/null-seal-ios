//! In-memory search index, built at unlock from the decrypted records of one vault and
//! dropped on lock. Haystacks are zeroized on drop; nothing here touches disk.

use crate::{Store, StoreError};
use core_crypto::Key;
use core_vault::{RecordContext, blob_key_gen, open_item};
use zeroize::Zeroizing;

struct Entry {
    id: String,
    /// Lowercased title, username, URLs, folder and tags (never the password or notes).
    haystack: Zeroizing<String>,
}

pub struct Index {
    entries: Vec<Entry>,
    /// Records that failed to authenticate or parse (tampered, or a newer schema/type).
    /// Surfaced so the caller can warn; they do not block unlock.
    pub skipped: Vec<String>,
}

impl Index {
    /// Decrypt every live record of `vault` and index it. `keys` is the vault's keyring as
    /// `(key_gen, key)`: a record is opened with the key of the generation its envelope names
    /// (older ones stay until a rotation has re-encrypted everything). Tombstones and trashed
    /// items are left out.
    pub fn build(store: &Store, vault: &str, keys: &[(u32, &Key)]) -> Result<Self, StoreError> {
        let (mut entries, mut skipped) = (Vec::new(), Vec::new());
        for rec in store.list(vault)?.into_iter().filter(|r| !r.tombstone) {
            let ctx = RecordContext {
                vault_id: rec.vault.as_bytes(),
                record_id: rec.id.as_bytes(),
                hlc: &rec.hlc,
                tombstone: false,
            };
            let vk = blob_key_gen(&rec.blob)
                .ok()
                .and_then(|g| keys.iter().find(|(kg, _)| *kg == g));
            match vk
                .ok_or(())
                .and_then(|(_, k)| open_item(k, &ctx, &rec.blob).map_err(drop))
            {
                Ok((_, p)) if p.data.deleted_at.is_none() => {
                    let d = &p.data;
                    let mut h = Zeroizing::new(String::new());
                    let parts = [&d.title]
                        .into_iter()
                        .chain(d.username.as_ref())
                        .chain(d.urls.iter().map(|u| &u.url))
                        .chain(d.folder.as_ref())
                        .chain(&d.tags);
                    for s in parts {
                        h.push_str(&s.to_lowercase());
                        h.push('\n');
                    }
                    entries.push(Entry {
                        id: rec.id,
                        haystack: h,
                    });
                }
                Ok(_) => {}
                Err(_) => skipped.push(rec.id),
            }
        }
        Ok(Self { entries, skipped })
    }

    /// Ids of items where every whitespace-separated term of `query` appears
    /// (case-insensitive substring). Empty query matches everything.
    pub fn search(&self, query: &str) -> Vec<&str> {
        let q = query.to_lowercase();
        let terms: Vec<&str> = q.split_whitespace().collect();
        self.entries
            .iter()
            .filter(|e| terms.iter().all(|t| e.haystack.contains(t)))
            .map(|e| e.id.as_str())
            .collect()
    }

    /// Drop every entry (each haystack is zeroized as it drops).
    pub fn clear(&mut self) {
        self.entries.clear();
        self.skipped.clear();
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}
