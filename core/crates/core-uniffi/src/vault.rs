//! Joining an existing vault from the iOS app (#86) and keeping it in sync.
//!
//! The core has no HTTP stack: Swift implements [`RelayTransport`] with URLSession and the
//! relay URL lives only in the on-device store (`Account` meta), never in this repo.

use core_crypto::Key;
use core_store::Store;
use core_sync::enroll::Joiner;
use core_sync::{Request, Response, SyncError, Transport, TransportError};
use core_vault::ItemType;
use seal_core::account::{Account, AccountError, LoginFields};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

/// What went wrong, with no detail that could carry a secret.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum VaultError {
    #[error("the code or relay address is not valid")]
    Invalid,
    #[error("the relay could not be reached")]
    Network,
    #[error("the relay refused the request")]
    Rejected,
    #[error("the master password is wrong")]
    WrongPassword,
    #[error("the vault is locked")]
    Locked,
    #[error("too many wrong attempts; try again shortly")]
    TryLater,
    #[error("the item no longer exists")]
    NotFound,
    #[error("this device already has a vault")]
    AlreadyJoined,
    #[error("device unlock is not set up")]
    NoDeviceUnlock,
    #[error("internal error")]
    Internal,
}

impl From<AccountError> for VaultError {
    fn from(e: AccountError) -> Self {
        use seal_core::session::SessionError;
        match e {
            AccountError::Session(SessionError::Locked) => Self::Locked,
            AccountError::Session(SessionError::Crypto) => Self::WrongPassword,
            AccountError::Session(SessionError::Delayed { .. }) => Self::TryLater,
            AccountError::NotFound => Self::NotFound,
            AccountError::NoDeviceUnlock => Self::NoDeviceUnlock,
            AccountError::Sync(e) => e.into(),
            _ => Self::Internal,
        }
    }
}

impl From<SyncError> for VaultError {
    fn from(e: SyncError) -> Self {
        match e {
            SyncError::Transport(_) | SyncError::Backoff(_) => Self::Network,
            SyncError::Status(_) => Self::Rejected,
            // a wrong code fails the MAC; a malformed one never reaches the network
            SyncError::Crypto => Self::Invalid,
            _ => Self::Internal,
        }
    }
}

/// One request header; UniFFI has no tuples.
#[derive(uniffi::Record)]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(uniffi::Record)]
pub struct RelayResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// HTTP to the relay, implemented in Swift. `path` is appended to the relay origin exactly as
/// given (it is part of the signed message); a non-2xx status is a response, not an error.
#[uniffi::export(with_foreign)]
pub trait RelayTransport: Send + Sync {
    fn send(
        &self,
        method: String,
        path: String,
        headers: Vec<Header>,
        body: Vec<u8>,
    ) -> Result<RelayResponse, VaultError>;
}

struct Bridge(Arc<dyn RelayTransport>);

impl Transport for Bridge {
    fn send(&self, req: &Request) -> Result<Response, TransportError> {
        let headers = req
            .headers
            .iter()
            .map(|(k, v)| Header {
                name: (*k).to_owned(),
                value: v.clone(),
            })
            .collect();
        self.0
            .send(
                req.method.to_owned(),
                req.path.clone(),
                headers,
                req.body.clone(),
            )
            .map(|r| Response {
                status: r.status,
                body: r.body,
            })
            .map_err(|e| TransportError(e.to_string()))
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// The relay must be https; plain http is only for an exact loopback host (development).
/// Userinfo, queries, fragments and odd characters are refused so the host cannot be disguised.
fn check_relay(url: &str) -> Result<(), VaultError> {
    if url.contains(|c: char| c.is_whitespace() || c.is_control() || "@?#\\".contains(c)) {
        return Err(VaultError::Invalid);
    }
    let authority = |rest: &str| rest.split('/').next().unwrap_or_default().to_owned();
    let ok = if let Some(rest) = url.strip_prefix("https://") {
        !authority(rest).is_empty()
    } else if let Some(rest) = url.strip_prefix("http://") {
        let a = authority(rest);
        let (host, port) = match a.rsplit_once(':') {
            Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
                (h.to_owned(), Some(p.to_owned()))
            }
            _ => (a.clone(), None),
        };
        matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]")
            && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    } else {
        false
    };
    if ok { Ok(()) } else { Err(VaultError::Invalid) }
}

/// A join in progress on a new device: the request is posted, the existing device has yet to
/// approve it. Nothing is stored until it does.
#[derive(uniffi::Object)]
pub struct Enrollment {
    joiner: Joiner,
    relay_url: String,
    transport: Arc<dyn RelayTransport>,
}

#[uniffi::export]
impl Enrollment {
    /// Validate the code and relay, then post this device's request to the relay.
    #[uniffi::constructor]
    pub fn start(
        code: String,
        relay_url: String,
        transport: Arc<dyn RelayTransport>,
    ) -> Result<Arc<Self>, VaultError> {
        let code = Zeroizing::new(code);
        let relay_url = relay_url.trim().trim_end_matches('/').to_owned();
        check_relay(&relay_url)?;
        let joiner = Joiner::new(&code).map_err(|_| VaultError::Invalid)?;
        joiner.send_request(&Bridge(transport.clone()))?;
        Ok(Arc::new(Self {
            joiner,
            relay_url,
            transport,
        }))
    }

    /// `None` while the existing device has not approved; once it has, the account is written
    /// to the store at `store_path` (locked) and the relay address is kept there.
    pub fn poll(&self, store_path: String) -> Result<Option<Arc<Vault>>, VaultError> {
        // refuse before the one-shot payload is read, so a refusal does not burn the approval
        let store = Store::open(&store_path).map_err(|_| VaultError::Internal)?;
        if Account::open(store)?.is_some() {
            return Err(VaultError::AlreadyJoined);
        }
        let Some(payload) = self.joiner.poll_result(&Bridge(self.transport.clone()))? else {
            return Ok(None);
        };
        let store = Store::open(&store_path).map_err(|_| VaultError::Internal)?;
        let account = Account::complete_join(store, &self.joiner, &payload, &self.relay_url)
            .map_err(VaultError::from)?;
        Ok(Some(Vault::wrap(account)))
    }
}

/// What an item is. Only logins and notes can be opened and edited on iOS so far.
#[derive(Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum ItemKind {
    Login,
    Note,
    Other,
}

/// One list row: no secrets.
#[derive(uniffi::Record)]
pub struct ItemRow {
    pub id: String,
    pub kind: ItemKind,
    pub title: String,
    pub username: String,
    pub url: String,
    pub favorite: bool,
    pub folder: String,
    pub tags: Vec<String>,
}

/// A login (or note) as shown in the detail and edit screens.
#[derive(uniffi::Record)]
pub struct LoginData {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

/// An item with a one-time code (a login's, or an authenticator entry's) and the seconds it stays valid.
#[derive(uniffi::Record)]
pub struct TotpEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub code: String,
    pub remaining: u32,
    pub period: u32,
}

/// The account on this device.
#[derive(uniffi::Object)]
pub struct Vault {
    account: Mutex<Account>,
    /// `lock()` arrived while a sync or unlock held the account; that call locks on its way out.
    lock_pending: AtomicBool,
}

impl Vault {
    fn wrap(account: Account) -> Arc<Self> {
        Arc::new(Self {
            account: Mutex::new(account),
            lock_pending: AtomicBool::new(false),
        })
    }

    fn account(&self) -> MutexGuard<'_, Account> {
        // a panic mid-call must not wedge the app; the account holds no invariant across calls
        self.account.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Run `f` on the account, then honour a `lock()` that came in meanwhile.
    fn with<T>(&self, f: impl FnOnce(&mut Account) -> T) -> T {
        let mut a = self.account();
        let out = f(&mut a);
        if self.lock_pending.swap(false, Ordering::SeqCst) {
            a.lock();
        }
        out
    }
}

/// The device key from Swift; the buffer is wiped once copied into the key.
fn device_key(bytes: Vec<u8>) -> Result<Key, VaultError> {
    let bytes = Zeroizing::new(bytes);
    <[u8; 32]>::try_from(bytes.as_slice())
        .map(Key::from_bytes)
        .map_err(|_| VaultError::Invalid)
}

/// The vault already on this device, locked; `None` before onboarding.
#[uniffi::export]
pub fn open_vault(store_path: String) -> Result<Option<Arc<Vault>>, VaultError> {
    let store = Store::open(&store_path).map_err(|_| VaultError::Internal)?;
    Ok(Account::open(store)?.map(Vault::wrap))
}

/// Counts from one sync round.
#[derive(uniffi::Record)]
pub struct SyncSummary {
    pub pushed: u32,
    pub pulled: u32,
}

#[uniffi::export]
impl Vault {
    pub fn unlock(&self, password: String) -> Result<(), VaultError> {
        let password = Zeroizing::new(password);
        self.lock_pending.store(false, Ordering::SeqCst);
        self.with(|a| a.unlock(&password, now_ms()))?;
        Ok(())
    }

    /// Whether this device holds a device-key wrapper (Face ID unlock, #88).
    pub fn device_unlock_enabled(&self) -> bool {
        self.account().device_unlock_enabled()
    }

    /// Wrap the Account Key under `key` (32 bytes the platform keeps behind biometry). Needs the
    /// vault unlocked.
    pub fn enable_device_unlock(&self, key: Vec<u8>) -> Result<(), VaultError> {
        let key = device_key(key)?;
        Ok(self.account().enable_device_unlock(&key)?)
    }

    /// Drop the wrapper; works locked, so a lost key never blocks the password path.
    pub fn disable_device_unlock(&self) -> Result<(), VaultError> {
        Ok(self.account().disable_device_unlock()?)
    }

    /// Unlock with the device key. A wrong key is `WrongPassword` and counts as a failed attempt.
    pub fn unlock_with_device_key(&self, key: Vec<u8>) -> Result<(), VaultError> {
        let key = device_key(key)?;
        self.lock_pending.store(false, Ordering::SeqCst);
        self.with(|a| a.unlock_with_device_key(&key, now_ms()))?;
        Ok(())
    }

    /// Where this device syncs; stored only in this device's database.
    pub fn relay_url(&self) -> Option<String> {
        self.account().relay_url().map(str::to_owned)
    }

    /// Never waits for a running sync: it locks at once, or as soon as that call returns.
    pub fn lock(&self) {
        self.lock_pending.store(true, Ordering::SeqCst);
        let mut a = match self.account.try_lock() {
            Ok(a) => a,
            Err(TryLockError::Poisoned(p)) => p.into_inner(),
            Err(TryLockError::WouldBlock) => return,
        };
        a.lock();
        self.lock_pending.store(false, Ordering::SeqCst);
    }

    pub fn is_unlocked(&self) -> bool {
        self.account().state() == seal_core::session::State::Unlocked
    }

    /// Push local edits and pull remote ones (needs the vault unlocked).
    pub fn sync(&self, transport: Arc<dyn RelayTransport>) -> Result<SyncSummary, VaultError> {
        let r = self.with(|a| a.sync_now(&Bridge(transport), now_ms()))?;
        Ok(SyncSummary {
            pushed: u32::try_from(r.pushed).unwrap_or(u32::MAX),
            pulled: u32::try_from(r.pulled).unwrap_or(u32::MAX),
        })
    }

    /// Every item, sorted by title (needs the vault unlocked).
    pub fn list_items(&self) -> Result<Vec<ItemRow>, VaultError> {
        Ok(self
            .account()
            .list_items()?
            .into_iter()
            .map(|i| ItemRow {
                id: i.id,
                kind: match i.item_type {
                    ItemType::Login => ItemKind::Login,
                    ItemType::Note => ItemKind::Note,
                    _ => ItemKind::Other,
                },
                title: i.title,
                username: i.username,
                url: i.url,
                favorite: i.favorite,
                folder: i.folder,
                tags: i.tags,
            })
            .collect())
    }

    /// Live codes of every item that has one, sorted by title. ponytail: decrypts each item
    /// twice (list, then code), fine for a personal vault; add `has_totp` to `ItemSummary` if it drags.
    pub fn totp_entries(&self) -> Result<Vec<TotpEntry>, VaultError> {
        let a = self.account();
        let now = now_ms();
        Ok(a.list_items()?
            .into_iter()
            .filter_map(|i| {
                let t = a.login_totp(&i.id, now).ok()??;
                Some(TotpEntry {
                    id: i.id,
                    title: i.title,
                    username: i.username,
                    code: t.code.to_string(),
                    remaining: t.remaining,
                    period: t.period,
                })
            })
            .collect())
    }

    pub fn get_login(&self, id: String) -> Result<LoginData, VaultError> {
        let f = self.account().get_login(&id)?;
        Ok(LoginData {
            title: f.title,
            username: f.username,
            password: f.password,
            url: f.url,
            notes: f.notes,
        })
    }

    /// Create (`id` = `None`) or update a login or note; returns the item id.
    pub fn save_login(&self, id: Option<String>, data: LoginData) -> Result<String, VaultError> {
        let f = LoginFields {
            title: data.title,
            username: data.username,
            password: data.password,
            url: data.url,
            notes: data.notes,
        };
        Ok(self.with(|a| a.save_login(id.as_deref(), &f, now_ms()))?)
    }

    pub fn delete_login(&self, id: String) -> Result<(), VaultError> {
        Ok(self.with(|a| a.delete_login(&id, now_ms()))?)
    }
}

#[cfg(test)]
mod tests;
