//! Encrypted local backups (#46, SR-15).
//!
//! A backup is one self-contained file: the account's public parameters and wrapped keys in
//! the clear (they already sit in the local store that way), and every stored record plus the
//! creation time sealed as a single envelope under a key derived from the Account Key.
//! Restoring on a clean profile therefore needs only the file and the master password (or the
//! recovery key), and any flipped bit, truncation or swapped header fails authentication
//! instead of restoring a vault that silently differs.
//!
//! ```text
//!   "NSBK" | version(1) | header_len(u32 BE) | header (Shared, JSON) | envelope(body)
//!   envelope = seal(HKDF(AK, "null-seal/v1/backup"), ak_gen, ctx("backup", everything before it), body)
//! ```
//!
//! A restored account is a new device: fresh device id and relay key, no relay configured. The
//! file never carries the old device's seed, so a backup cannot clone a device identity.

use super::*;
use core_crypto::hkdf;
use core_keys::unwrap_account_key;
use core_sync::hlc;

const MAGIC: &[u8; 4] = b"NSBK";
const VERSION: u8 = 1;
/// Bounds for the untrusted file (SR-23): header and whole file.
const MAX_HEADER: usize = 64 * 1024;
const MAX_FILE: usize = 256 * 1024 * 1024;
const LAST_BACKUP: &str = "last_backup";

/// What opens a backup: the master password or the recovery code shown at setup.
pub enum BackupSecret<'a> {
    Password(&'a str),
    Recovery(&'a str),
}

/// What a verified backup contains.
#[derive(Debug, PartialEq, Eq)]
pub struct BackupInfo {
    /// Unix ms the backup was taken.
    pub created_ms: u64,
    /// Items that were live when it was taken (deleted ones are kept as tombstones).
    pub items: usize,
}

#[derive(Serialize, Deserialize)]
struct Body {
    created_ms: u64,
    records: Vec<Rec>,
}

#[derive(Serialize, Deserialize)]
struct Rec {
    id: String,
    vault: String,
    hlc: String,
    tomb: bool,
    blob: String,
}

fn backup_key(ak: &Key) -> Result<Key, AccountError> {
    Ok(hkdf(ak.expose(), None, b"null-seal/v1/backup")?)
}

fn backup_ctx(header: &[u8]) -> Vec<u8> {
    context(&[b"backup", header])
}

impl Account {
    /// Snapshot every record into an encrypted backup file. Needs the account unlocked; write
    /// the bytes somewhere durable, then call [`Account::mark_backed_up`].
    pub fn backup(&self, now_ms: u64) -> Result<Vec<u8>, AccountError> {
        self.backup_file(now_ms, true)
    }

    /// `with_master` false leaves the master-password wrapper out of the clear header, for copies
    /// that leave the device (see [`backup_to_relay`](Self::backup_to_relay)).
    fn backup_file(&self, now_ms: u64, with_master: bool) -> Result<Vec<u8>, AccountError> {
        let ak = self.session.account_key()?;
        let mut header_data = self.meta.shared.clone();
        if !with_master {
            header_data.master_wrapper.clear();
        }
        let shared = serde_json::to_vec(&header_data).map_err(|_| AccountError::Format)?;
        let mut records = Vec::new();
        for v in &self.meta.shared.vaults {
            for r in self.store.list(&v.id)? {
                records.push(Rec {
                    id: r.id,
                    vault: r.vault,
                    hlc: r.hlc,
                    tomb: r.tombstone,
                    blob: b64(&r.blob),
                });
            }
        }
        let body = Zeroizing::new(
            serde_json::to_vec(&Body {
                created_ms: now_ms,
                records,
            })
            .map_err(|_| AccountError::Format)?,
        );
        let header_len = u32::try_from(shared.len()).map_err(|_| AccountError::Format)?;
        let mut out = [
            MAGIC.as_slice(),
            &[VERSION],
            &header_len.to_be_bytes(),
            &shared,
        ]
        .concat();
        let env = seal(
            &backup_key(ak)?,
            self.meta.shared.ak_gen,
            &backup_ctx(&out),
            &body,
        )?;
        out.extend_from_slice(&env);
        Ok(out)
    }

    /// Remember that a backup was written at `now_ms`, once the caller has stored the file.
    pub fn mark_backed_up(&self, now_ms: u64) -> Result<(), AccountError> {
        Ok(self
            .store
            .meta_set(LAST_BACKUP, now_ms.to_string().as_bytes())?)
    }

    /// Whether the last backup is at least `interval_ms` old, or there never was one. The
    /// caller owns the timer; this is the schedule's single decision.
    pub fn backup_due(&self, now_ms: u64, interval_ms: u64) -> Result<bool, AccountError> {
        let last = self
            .store
            .meta_get(LAST_BACKUP)?
            .and_then(|b| String::from_utf8(b).ok())
            .and_then(|s| s.parse::<u64>().ok());
        Ok(last.is_none_or(|l| now_ms.saturating_sub(l) >= interval_ms))
    }

    /// Take a backup and upload it to the relay's R2 bucket (#47), returning its name there. The
    /// relay cannot read it, and it holds no master-password wrapper (SR-1): anyone who can read
    /// the bucket has nothing to guess a password against, only a 256-bit recovery key. So it
    /// restores with the recovery code, after which
    /// [`reset_master_password`](Self::reset_master_password) sets a new master password.
    /// Fails with `Status(501)` if the owner did not enable R2 backups. The caller owns the
    /// timer (see [`backup_due`](Self::backup_due)).
    pub fn backup_to_relay(
        &self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<String, AccountError> {
        let file = self.backup_file(now_ms, false)?;
        Ok(core_sync::backup::upload(
            transport,
            self.device()?,
            now_ms,
            &file,
        )?)
    }

    /// The backups the relay holds, newest first.
    pub fn relay_backups(
        &self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<Vec<core_sync::backup::RemoteBackup>, AccountError> {
        Ok(core_sync::backup::list(transport, self.device()?, now_ms)?)
    }

    /// Fetch one relay backup as a file for [`Account::restore`] or [`verify_backup`], which
    /// authenticate it. With no enrolled device left, fetch the object from your own R2 bucket and
    /// pass its text through `core_sync::backup::decode` instead.
    pub fn download_relay_backup(
        &self,
        transport: &dyn Transport,
        now_ms: u64,
        key: &str,
    ) -> Result<Vec<u8>, AccountError> {
        Ok(core_sync::backup::download(
            transport,
            self.device()?,
            now_ms,
            key,
        )?)
    }

    /// Restore a backup into an empty store, as a new locked device of the account. Nothing is
    /// written unless the whole file authenticates, and the account entry is written last, so
    /// a failed restore leaves a store that can simply try again.
    pub fn restore(
        store: Store,
        file: &[u8],
        secret: &BackupSecret,
        now_ms: u64,
    ) -> Result<Self, AccountError> {
        Ok(restore(store, file, secret, now_ms)?.0)
    }
}

/// Check that a backup opens and is intact without touching any real store.
pub fn verify_backup(
    file: &[u8],
    secret: &BackupSecret,
    now_ms: u64,
) -> Result<BackupInfo, AccountError> {
    Ok(restore(Store::open_in_memory()?, file, secret, now_ms)?.1)
}

fn restore(
    store: Store,
    file: &[u8],
    secret: &BackupSecret,
    now_ms: u64,
) -> Result<(Account, BackupInfo), AccountError> {
    if store.meta_get(META_KEY)?.is_some() {
        return Err(AccountError::Format); // never overwrite an existing vault
    }
    if file.len() > MAX_FILE {
        return Err(AccountError::BackupCorrupt);
    }
    let rest = file
        .strip_prefix(MAGIC.as_slice())
        .and_then(|r| r.split_first())
        .filter(|(v, _)| **v == VERSION)
        .map(|(_, r)| r)
        .ok_or(AccountError::BackupCorrupt)?;
    let (len, rest) = rest
        .split_first_chunk::<4>()
        .ok_or(AccountError::BackupCorrupt)?;
    let len = usize::try_from(u32::from_be_bytes(*len)).unwrap_or(usize::MAX);
    if len > MAX_HEADER || len > rest.len() {
        return Err(AccountError::BackupCorrupt);
    }
    let (shared_json, env) = rest.split_at(len);
    let header = &file[..file.len() - env.len()];
    let shared: Shared =
        serde_json::from_slice(shared_json).map_err(|_| AccountError::BackupCorrupt)?;
    let mh = header_of(&shared).map_err(|_| AccountError::BackupCorrupt)?;

    let master = unb64(&shared.master_wrapper)?;
    let recovery = unb64(&shared.recovery_wrapper)?;
    let ak = match secret {
        BackupSecret::Password(_) if shared.master_wrapper.is_empty() => {
            return Err(AccountError::NeedsRecoveryCode);
        }
        BackupSecret::Password(p) => unwrap_account_key(
            &master,
            &Wrapper::Master {
                password: p,
                header: &mh,
            },
        )
        .ok(),
        BackupSecret::Recovery(code) => decode_recovery_key(code)
            .ok()
            .and_then(|k| unwrap_account_key(&recovery, &Wrapper::Recovery(&k)).ok()),
    }
    .ok_or(AccountError::Crypto)?;

    let (gen_, plain) = open(&backup_key(&ak)?, &backup_ctx(header), env)
        .map_err(|_| AccountError::BackupCorrupt)?;
    if gen_ != shared.ak_gen {
        return Err(AccountError::BackupCorrupt);
    }
    let body: Body = serde_json::from_slice(&plain).map_err(|_| AccountError::BackupCorrupt)?;

    let mut records = Vec::with_capacity(body.records.len());
    for r in body.records {
        if !shared.vaults.iter().any(|v| v.id == r.vault) || hlc::parse(&r.hlc).is_none() {
            return Err(AccountError::BackupCorrupt);
        }
        records.push(Record {
            id: r.id,
            vault: r.vault,
            hlc: r.hlc,
            tombstone: r.tomb,
            blob: unb64(&r.blob).map_err(|_| AccountError::BackupCorrupt)?,
        });
    }

    let device_id = random_id()?;
    let seed = Key::random()?;
    let meta = Meta {
        device_seed: b64(&seal(
            &ak,
            shared.ak_gen,
            &seed_ctx(&device_id),
            seed.expose(),
        )?),
        device_id,
        relay_url: None,
        attested: None,
        attested_vaults: 0,
        acct_published: None,
        device_wrapper: None,
        shared,
    };
    for r in &records {
        store.put(r)?;
    }
    save_meta(&store, &meta)?;
    let mut acct = Account::from_parts(store, meta)?;
    // new edits must sort after everything restored
    for r in &records {
        acct.clock.observe(&r.hlc, now_ms);
    }
    acct.clock.persist(&acct.store)?;
    let items = records.iter().filter(|r| !r.tombstone).count();
    Ok((
        acct,
        BackupInfo {
            created_ms: body.created_ms,
            items,
        },
    ))
}

#[cfg(test)]
mod tests;
