//! Session state machine (SR-12): keys and the search index exist in memory only while
//! `Unlocked`. Everything that reads or writes items goes through the session, so there is
//! no way to touch plaintext once it is locked.
//!
//! ```text
//!   Locked --begin_unlock--> Unlocking --finish_unlock(ok)--> Unlocked
//!      ^                         |  (failure)                    |
//!      +-------------------------+-------- lock / idle tick -----+
//! ```
//!
//! The core has no timers and no clock. The platform passes a monotonic millisecond
//! reading (`now_ms`) and calls [`Session::touch`] on user activity and [`Session::tick`]
//! periodically; OS events (sleep, screen lock) call [`Session::lock`].
//!
//! Unlocking is split in two so the slow part (Argon2id, index build) can run on a worker
//! thread while the UI shows `Unlocking`: [`Opened::open`] is a plain function, and
//! [`Session::unlock`] does all three steps inline.

use core_crypto::Key;
use core_keys::{Wrapper, unwrap_account_key, unwrap_vault_key};
use core_store::{Index, Record, Store, StoreError};
use core_vault::{Payload, RecordContext, VaultError, blob_key_gen, open_item, seal_item};
use zeroize::Zeroize;

/// Idle time before auto-lock unless the platform changes it.
pub const DEFAULT_IDLE_TIMEOUT_MS: u64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Locked,
    Unlocking,
    Unlocked,
}

#[derive(Debug)]
pub enum SessionError {
    /// Operation needs an unlocked session.
    Locked,
    /// Transition not allowed from the current state (e.g. unlock while unlocked).
    WrongState,
    /// Too many recent failures: retry after this many milliseconds.
    Delayed {
        retry_in_ms: u64,
    },
    /// Wrong password/key, or a tampered wrapper. Counts as a failed attempt.
    Crypto,
    NoSuchVault,
    /// The record is sealed under a key generation this session does not hold.
    UnknownKeyGen(u32),
    Vault(VaultError),
    Store(StoreError),
}

impl From<StoreError> for SessionError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<VaultError> for SessionError {
    fn from(e: VaultError) -> Self {
        Self::Vault(e)
    }
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Locked => f.write_str("vault is locked"),
            Self::WrongState => f.write_str("not allowed in the current session state"),
            Self::Delayed { retry_in_ms } => {
                write!(f, "too many attempts, retry in {retry_in_ms} ms")
            }
            Self::Crypto => f.write_str("could not unlock"),
            Self::NoSuchVault => f.write_str("no such vault"),
            Self::UnknownKeyGen(g) => write!(f, "record uses unknown key generation {g}"),
            Self::Vault(e) => e.fmt(f),
            Self::Store(e) => e.fmt(f),
        }
    }
}

impl core::error::Error for SessionError {}

/// How long to refuse further attempts after `failures` consecutive wrong secrets:
/// none for the first two, then 1 s doubling up to 60 s.
pub fn failed_attempt_delay_ms(failures: u32) -> u64 {
    match failures {
        0..=2 => 0,
        n => (1000u64 << (n - 3).min(6)).min(60_000),
    }
}

/// A vault to open: its id, the VK generation bound into its wrapper, and the VK blob
/// wrapped by the Account Key, plus the earlier generations (`(key_gen, wrapped)`) kept after a
/// rotation so records not yet re-encrypted stay readable.
pub struct VaultEntry {
    pub id: String,
    pub key_gen: u32,
    pub wrapped_key: Vec<u8>,
    pub old: Vec<(u32, Vec<u8>)>,
}

struct OpenVault {
    id: String,
    key_gen: u32,
    vk: Key,
    /// Earlier generations, readable only (never used to seal).
    old: Vec<(u32, Key)>,
    index: Index,
}

impl OpenVault {
    /// Current key first, then older generations.
    fn keyring(&self) -> Vec<(u32, &Key)> {
        let cur = (self.key_gen, &self.vk);
        std::iter::once(cur)
            .chain(self.old.iter().map(|(g, k)| (*g, k)))
            .collect()
    }
}

/// Unwrap one vault's keys with the Account Key and index its records.
fn open_vault(store: &Store, ak: &Key, v: &VaultEntry) -> Result<OpenVault, SessionError> {
    let unwrap = |g: u32, blob: &[u8]| {
        unwrap_vault_key(ak, v.id.as_bytes(), g, blob).map_err(|_| SessionError::Crypto)
    };
    let vk = unwrap(v.key_gen, &v.wrapped_key)?;
    let old = v
        .old
        .iter()
        .map(|(g, blob)| Ok((*g, unwrap(*g, blob)?)))
        .collect::<Result<Vec<_>, SessionError>>()?;
    let ring: Vec<_> = std::iter::once((v.key_gen, &vk))
        .chain(old.iter().map(|(g, k)| (*g, k)))
        .collect();
    let index = Index::build(store, &v.id, &ring)?;
    Ok(OpenVault {
        id: v.id.clone(),
        key_gen: v.key_gen,
        vk,
        old,
        index,
    })
}

/// Keys and indexes of every opened vault. Wiped on drop, so any path that lets go of it
/// (lock, idle tick, cancelled unlock, session dropped) zeroizes the keys.
pub struct Opened {
    ak: Key,
    vaults: Vec<OpenVault>,
}

impl Opened {
    /// The slow half of unlocking: open the Account Key with `wrapper`, then each Vault Key,
    /// and build the search index. The Account Key stays in memory while unlocked (it seals
    /// the device's relay key and delivers keys to a new device) and is zeroized with the rest.
    pub fn open(
        store: &Store,
        wrapper: &Wrapper,
        ak_wrapper: &[u8],
        vaults: &[VaultEntry],
    ) -> Result<Self, SessionError> {
        let ak = unwrap_account_key(ak_wrapper, wrapper).map_err(|_| SessionError::Crypto)?;
        Self::with_account_key(store, ak, vaults)
    }

    /// Open the vaults with an Account Key already in hand (after a key rotation was received).
    pub fn with_account_key(
        store: &Store,
        ak: Key,
        vaults: &[VaultEntry],
    ) -> Result<Self, SessionError> {
        let out = vaults
            .iter()
            .map(|v| open_vault(store, &ak, v))
            .collect::<Result<_, _>>()?;
        Ok(Self { ak, vaults: out })
    }

    fn vault(&self, id: &str) -> Result<&OpenVault, SessionError> {
        self.vaults
            .iter()
            .find(|v| v.id == id)
            .ok_or(SessionError::NoSuchVault)
    }

    fn wipe(&mut self) {
        self.ak.zeroize();
        for v in &mut self.vaults {
            v.vk.zeroize();
            v.old.iter_mut().for_each(|(_, k)| k.zeroize());
            v.index.clear();
        }
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        self.wipe();
    }
}

enum Inner {
    Locked,
    Unlocking,
    Unlocked(Opened),
}

pub struct Session {
    inner: Inner,
    failures: u32,
    next_attempt_ms: u64,
    idle_timeout_ms: Option<u64>,
    last_activity_ms: u64,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            inner: Inner::Locked,
            failures: 0,
            next_attempt_ms: 0,
            idle_timeout_ms: Some(DEFAULT_IDLE_TIMEOUT_MS),
            last_activity_ms: 0,
        }
    }
}

impl Session {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> State {
        match self.inner {
            Inner::Locked => State::Locked,
            Inner::Unlocking => State::Unlocking,
            Inner::Unlocked(_) => State::Unlocked,
        }
    }

    /// `None` disables auto-lock.
    pub fn set_idle_timeout(&mut self, ms: Option<u64>) {
        self.idle_timeout_ms = ms;
    }

    /// Locked -> Unlocking, unless attempts are currently delayed.
    pub fn begin_unlock(&mut self, now_ms: u64) -> Result<(), SessionError> {
        if !matches!(self.inner, Inner::Locked) {
            return Err(SessionError::WrongState);
        }
        if now_ms < self.next_attempt_ms {
            return Err(SessionError::Delayed {
                retry_in_ms: self.next_attempt_ms - now_ms,
            });
        }
        self.inner = Inner::Unlocking;
        Ok(())
    }

    /// Unlocking -> Unlocked on success, back to Locked on failure. A wrong secret counts
    /// towards the delay; other errors (e.g. a store problem) do not. If the session was
    /// locked meanwhile, the result is discarded (and its keys wiped).
    pub fn finish_unlock(
        &mut self,
        now_ms: u64,
        result: Result<Opened, SessionError>,
    ) -> Result<(), SessionError> {
        if !matches!(self.inner, Inner::Unlocking) {
            return Err(SessionError::WrongState);
        }
        match result {
            Ok(opened) => {
                self.failures = 0;
                self.next_attempt_ms = 0;
                self.last_activity_ms = now_ms;
                self.inner = Inner::Unlocked(opened);
                Ok(())
            }
            Err(e) => {
                if matches!(e, SessionError::Crypto) {
                    self.failures = self.failures.saturating_add(1);
                    self.next_attempt_ms =
                        now_ms.saturating_add(failed_attempt_delay_ms(self.failures));
                }
                self.inner = Inner::Locked;
                Err(e)
            }
        }
    }

    /// All three steps inline.
    pub fn unlock(
        &mut self,
        now_ms: u64,
        store: &Store,
        wrapper: &Wrapper,
        ak_wrapper: &[u8],
        vaults: &[VaultEntry],
    ) -> Result<(), SessionError> {
        self.begin_unlock(now_ms)?;
        self.finish_unlock(now_ms, Opened::open(store, wrapper, ak_wrapper, vaults))
    }

    /// Any state -> Locked. Keys are zeroized and indexes dropped (also cancels an unlock
    /// in progress). Idempotent.
    pub fn lock(&mut self) {
        self.inner = Inner::Locked;
    }

    /// Record user activity, pushing the idle deadline out.
    pub fn touch(&mut self, now_ms: u64) {
        if matches!(self.inner, Inner::Unlocked(_)) {
            self.last_activity_ms = self.last_activity_ms.max(now_ms);
        }
    }

    /// When the idle timeout will lock the session (None: locked, or no timeout configured).
    pub fn idle_deadline_ms(&self) -> Option<u64> {
        match self.inner {
            Inner::Unlocked(_) => self
                .idle_timeout_ms
                .map(|t| self.last_activity_ms.saturating_add(t)),
            _ => None,
        }
    }

    /// Lock if the idle timeout has passed. Returns whether it locked.
    pub fn tick(&mut self, now_ms: u64) -> bool {
        let expired = matches!(self.inner, Inner::Unlocked(_))
            && self
                .idle_timeout_ms
                .is_some_and(|t| now_ms.saturating_sub(self.last_activity_ms) >= t);
        if expired {
            self.lock();
        }
        expired
    }

    fn opened(&self) -> Result<&Opened, SessionError> {
        match &self.inner {
            Inner::Unlocked(o) => Ok(o),
            _ => Err(SessionError::Locked),
        }
    }

    /// The Account Key, for wrapping per-device secrets and enrolling new devices. Crate-private
    /// so no binding can expose it.
    pub(crate) fn account_key(&self) -> Result<&Key, SessionError> {
        Ok(&self.opened()?.ak)
    }

    /// Replace every key with a rotated set (a received key rotation, #44). Unlocked only; the
    /// old keys are zeroized as they drop. On error nothing changes.
    pub(crate) fn rekey(
        &mut self,
        store: &Store,
        ak: Key,
        vaults: &[VaultEntry],
    ) -> Result<(), SessionError> {
        self.opened()?;
        self.inner = Inner::Unlocked(Opened::with_account_key(store, ak, vaults)?);
        Ok(())
    }

    /// Open one more vault (a newly created one) without touching the others. Unlocked only.
    pub(crate) fn add_vault(&mut self, store: &Store, v: &VaultEntry) -> Result<(), SessionError> {
        let Inner::Unlocked(o) = &mut self.inner else {
            return Err(SessionError::Locked);
        };
        let ov = open_vault(store, &o.ak, v)?;
        o.vaults.push(ov);
        Ok(())
    }

    /// Generation of the key new records of `vault_id` are sealed under.
    pub(crate) fn key_gen(&self, vault_id: &str) -> Result<u32, SessionError> {
        Ok(self.opened()?.vault(vault_id)?.key_gen)
    }

    /// Every key of a vault as `(key_gen, key)`, current first. Crate-private like the
    /// Account Key: a rotation re-wraps them, nothing else may see them.
    pub(crate) fn keyring(&self, vault_id: &str) -> Result<Vec<(u32, &Key)>, SessionError> {
        Ok(self.opened()?.vault(vault_id)?.keyring())
    }

    /// Ids of matching items in a vault (see [`Index::search`]).
    pub fn search(&self, vault_id: &str, query: &str) -> Result<Vec<&str>, SessionError> {
        Ok(self.opened()?.vault(vault_id)?.index.search(query))
    }

    /// Records that failed to open when the vault was indexed.
    pub fn skipped(&self, vault_id: &str) -> Result<&[String], SessionError> {
        Ok(&self.opened()?.vault(vault_id)?.index.skipped)
    }

    /// Decrypt a stored record with the key of the generation its envelope names.
    pub fn open_record(&self, rec: &Record) -> Result<Payload, SessionError> {
        let v = self.opened()?.vault(&rec.vault)?;
        let key_gen = blob_key_gen(&rec.blob)?;
        let (_, vk) = v
            .keyring()
            .into_iter()
            .find(|(g, _)| *g == key_gen)
            .ok_or(SessionError::UnknownKeyGen(key_gen))?;
        let ctx = RecordContext {
            vault_id: rec.vault.as_bytes(),
            record_id: rec.id.as_bytes(),
            hlc: &rec.hlc,
            tombstone: rec.tombstone,
        };
        Ok(open_item(vk, &ctx, &rec.blob)?.1)
    }

    /// Seal a payload into a record ready for [`Store::put`].
    pub fn seal_record(
        &self,
        vault_id: &str,
        record_id: &str,
        hlc: &str,
        tombstone: bool,
        payload: &Payload,
    ) -> Result<Record, SessionError> {
        let v = self.opened()?.vault(vault_id)?;
        let ctx = RecordContext {
            vault_id: vault_id.as_bytes(),
            record_id: record_id.as_bytes(),
            hlc,
            tombstone,
        };
        Ok(Record {
            id: record_id.into(),
            vault: vault_id.into(),
            hlc: hlc.into(),
            tombstone,
            blob: seal_item(&v.vk, v.key_gen, &ctx, payload)?,
        })
    }

    /// Rebuild a vault's search index after records changed.
    pub fn refresh_index(&mut self, store: &Store, vault_id: &str) -> Result<(), SessionError> {
        let Inner::Unlocked(o) = &mut self.inner else {
            return Err(SessionError::Locked);
        };
        let v = o
            .vaults
            .iter_mut()
            .find(|v| v.id == vault_id)
            .ok_or(SessionError::NoSuchVault)?;
        v.index = Index::build(store, vault_id, &v.keyring())?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
