//! The account facade: everything a client (desktop, later iOS) does with one vault, behind
//! one API so no key or plaintext handling is re-implemented per platform.
//!
//! ```text
//!   begin_setup -> (Setup, recovery code) --confirm(retyped code)--> Account (unlocked)
//!   Account::open -> Locked --unlock(password)--> Unlocked --lock / idle--> Locked
//!   join (new device): Joiner --payload from an enrolled device--> Account (locked)
//! ```
//!
//! Persistent state is the SQLite store: encrypted records plus one `account` entry in its
//! meta table that holds only public parameters and ciphertext (wrapped keys, the device's
//! relay seed sealed under the Account Key). `now_ms` is wall-clock Unix milliseconds
//! throughout: it drives the HLC, request signing and the idle timer.

use crate::session::{Session, SessionError, State, VaultEntry};

mod audit;
mod backup;
mod device_unlock;
mod export;
mod history;
mod import;
mod items;
mod organize;
mod password;
mod rotate;
mod vaults;
pub use audit::{Audit, AuditItem, BreachProbe, check_breaches};
pub use backup::{BackupInfo, BackupSecret, verify_backup};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use core_crypto::{KdfParams, Key, random_bytes, sha256};
use core_keys::{
    MasterHeader, PW_NORM, Wrapper, context, decode_recovery_key, encode_recovery_key,
    new_account_key, new_recovery_key, new_vault_key, open, seal, verify_retyped, wrap_account_key,
    wrap_vault_key,
};
use core_otp::{Kind, Otp};
use core_store::{Record, Store, StoreError};
use core_sync::devices;
use core_sync::enroll::{JoinRequest, Joiner, Offer};
use core_sync::{Clock, Device, Resolution, SyncError, SyncReport, Transport, Verdict, lww};
pub use core_vault::ItemType;
use core_vault::merge::{Merged, Side, merge, stamp_changes};
use core_vault::{Item, Payload, Url, blob_key_gen};
pub use export::PlainExport;
pub use history::LoginVersion;
pub use import::ImportSummary;
pub use items::{ItemFields, OtpImport, generate_ssh_key, ssh_key_info};
pub use organize::Organization;
pub use rotate::{DeviceInfo, Revocation, RevocationReport};
use serde::{Deserialize, Serialize};
pub use vaults::VaultInfo;
use zeroize::Zeroizing;

const META_KEY: &str = "account";
pub const MIN_PASSWORD_CHARS: usize = 12;
/// zxcvbn score required of a master password (ADR 0001: no Secret Key in v1).
pub const MIN_PASSWORD_SCORE: u8 = 3;

#[derive(Debug)]
pub enum AccountError {
    /// Master password too short or too guessable.
    WeakPassword,
    /// The retyped recovery key does not match.
    RecoveryMismatch,
    Session(SessionError),
    Sync(SyncError),
    Store(StoreError),
    /// Stored account data is not what this build writes.
    Format,
    Crypto,
    NoRelay,
    NotFound,
    /// The backup file is damaged, tampered with or not a backup.
    BackupCorrupt,
    /// A device cannot revoke itself; revoke it from another one.
    RevokeSelf,
    /// The relay has no device with this id.
    UnknownDevice,
    /// The backup predates a key rotation (a revoke), so its Account Key is retired and the relay
    /// will not take this device back. Restore a newer backup, or enroll a fresh device instead.
    StaleBackup,
    /// This account has no master-password wrapper (it was restored from a relay backup): use the
    /// recovery code, then set a new master password.
    NeedsRecoveryCode,
    /// This device has no device wrapper (device unlock is off): use the master password.
    NoDeviceUnlock,
    /// These devices have not confirmed themselves to the account yet (they sync at least
    /// once after enrolling), so keys cannot be delivered to them safely: revoke them too,
    /// or let them sync and try again.
    UnverifiedDevices(Vec<String>),
    /// An account-encrypted Bitwarden export: only that Bitwarden account can read it. Re-export
    /// as unencrypted or password-protected JSON.
    ImportEncrypted,
    /// A password-protected Bitwarden export: ask for its password and use
    /// [`Account::import_bitwarden_password`].
    ImportPasswordRequired,
    /// The password does not open this Bitwarden export. Nothing was imported.
    ImportWrongPassword,
    /// A malformed or unsupported authenticator secret, link or QR image.
    Otp(core_otp::Error),
    /// A malformed, passphrase-protected or unsupported SSH private key.
    Ssh(core_ssh::Error),
}

macro_rules! from {
    ($t:ty, $v:ident) => {
        impl From<$t> for AccountError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from!(SessionError, Session);
from!(SyncError, Sync);
from!(StoreError, Store);

impl From<core_crypto::Error> for AccountError {
    fn from(_: core_crypto::Error) -> Self {
        Self::Crypto
    }
}
impl From<core_sync::hlc::ClockError> for AccountError {
    fn from(e: core_sync::hlc::ClockError) -> Self {
        Self::Sync(e.into())
    }
}

impl core::fmt::Display for AccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WeakPassword => write!(
                f,
                "master password must be at least {MIN_PASSWORD_CHARS} characters and not easy to guess"
            ),
            Self::RecoveryMismatch => f.write_str("the recovery key does not match"),
            Self::Session(e) => e.fmt(f),
            Self::Sync(e) => e.fmt(f),
            Self::Store(e) => e.fmt(f),
            Self::Format => f.write_str("stored account data is invalid"),
            Self::Crypto => f.write_str("crypto error"),
            Self::NoRelay => f.write_str("no relay is configured"),
            Self::NotFound => f.write_str("item not found"),
            Self::BackupCorrupt => f.write_str("the backup is damaged or not a backup"),
            Self::RevokeSelf => f.write_str("a device cannot revoke itself"),
            Self::UnknownDevice => f.write_str("no such device"),
            Self::NeedsRecoveryCode => f.write_str(
                "this copy has no master password; use the recovery code and set a new password",
            ),
            Self::NoDeviceUnlock => f.write_str("device unlock is not set up; use the master password"),
            Self::StaleBackup => f.write_str(
                "the backup predates a key rotation; restore a newer backup or enroll a new device",
            ),
            Self::UnverifiedDevices(ids) => write!(
                f,
                "devices {} have not synced since enrolling; revoke them or sync them first",
                ids.join(", ")
            ),
            Self::Otp(e) => e.fmt(f),
            Self::Ssh(e) => e.fmt(f),
            Self::ImportEncrypted => f.write_str(
                "this Bitwarden export is encrypted with the Bitwarden account key; export it again as unencrypted or password-protected JSON",
            ),
            Self::ImportPasswordRequired => {
                f.write_str("this Bitwarden export is password-protected; enter its password")
            }
            Self::ImportWrongPassword => {
                f.write_str("that password does not open this Bitwarden export")
            }
        }
    }
}

impl core::error::Error for AccountError {}

/// Public parameters and wrapped keys shared by every device of the account.
#[derive(Clone, Serialize, Deserialize)]
struct Shared {
    account_id: String,
    /// Argon2id m (KiB), t, p.
    kdf: [u32; 3],
    salt: String,
    pw_norm: u8,
    master_wrapper: String,
    recovery_wrapper: String,
    /// Generation of the Account Key; a key rotation (#44) raises it.
    #[serde(default)]
    ak_gen: u32,
    vaults: Vec<VaultMeta>,
}

#[derive(Clone, Serialize, Deserialize)]
struct VaultMeta {
    id: String,
    key_gen: u32,
    wrapped_key: String,
    /// Earlier Vault Key generations, kept so records not yet re-encrypted stay readable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    old: Vec<OldKey>,
    /// Display name sealed under the Account Key (never in the clear); empty = the first vault.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct OldKey {
    key_gen: u32,
    wrapped_key: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct Meta {
    #[serde(flatten)]
    shared: Shared,
    device_id: String,
    relay_url: Option<String>,
    /// This device's relay signing seed, sealed under the Account Key.
    device_seed: String,
    /// Account Key generation this device last published its attestation for.
    #[serde(default)]
    attested: Option<u32>,
    /// How many vaults that attestation listed (#130); it is republished when the count grows.
    #[serde(default)]
    attested_vaults: usize,
    /// Account Key generation whose account-auth key this device last published (#124).
    #[serde(default)]
    acct_published: Option<u32>,
    /// The Account Key wrapped under a key only this device can produce (#76). Local: never in
    /// [`Shared`], so never synced or handed to another device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_wrapper: Option<String>,
}

/// What an enrolled device hands to a new one (sealed in transit by the enrollment protocol).
#[derive(Serialize, Deserialize)]
struct Bundle {
    #[serde(flatten)]
    shared: Shared,
    ak: String,
}

fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

fn unb64(s: &str) -> Result<Vec<u8>, AccountError> {
    B64.decode(s).map_err(|_| AccountError::Format)
}

fn random_id() -> Result<String, AccountError> {
    Ok(random_bytes::<16>()?
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect())
}

fn node_of(device_id: &str) -> u32 {
    let h = sha256(device_id.as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

fn seed_ctx(device_id: &str) -> Vec<u8> {
    context(&[b"device-seed", device_id.as_bytes()])
}

/// Reject weak master passwords (setup and password change).
pub fn check_password(password: &str) -> Result<(), AccountError> {
    if password.chars().count() < MIN_PASSWORD_CHARS
        || core_gen::estimate(password, &[]).score < MIN_PASSWORD_SCORE
    {
        return Err(AccountError::WeakPassword);
    }
    Ok(())
}

fn vault_entries(s: &Shared) -> Result<Vec<VaultEntry>, AccountError> {
    s.vaults
        .iter()
        .map(|v| {
            Ok(VaultEntry {
                id: v.id.clone(),
                key_gen: v.key_gen,
                wrapped_key: unb64(&v.wrapped_key)?,
                old: v
                    .old
                    .iter()
                    .map(|o| Ok((o.key_gen, unb64(&o.wrapped_key)?)))
                    .collect::<Result<_, AccountError>>()?,
            })
        })
        .collect()
}

fn header_of(s: &Shared) -> Result<MasterHeader, AccountError> {
    let salt = unb64(&s.salt)?
        .try_into()
        .map_err(|_| AccountError::Format)?;
    // KdfParams::new enforces the floor and ceiling, so a downgraded header is refused (SR-3).
    let params = KdfParams::new(s.kdf[0], s.kdf[1], s.kdf[2]).map_err(|_| AccountError::Format)?;
    Ok(MasterHeader {
        salt,
        params,
        pw_norm: s.pw_norm,
    })
}

/// First-run state: the vault exists in memory only, until the recovery key is retyped.
pub struct Setup {
    store: Option<Store>,
    meta: Meta,
    recovery: Key,
    password: Zeroizing<String>,
}

/// Start creating an account: generates every key and the recovery code to show once.
/// Nothing is written to the store until [`Setup::confirm`] succeeds.
pub fn begin_setup(
    store: Store,
    password: &str,
    params: KdfParams,
) -> Result<(Setup, Zeroizing<String>), AccountError> {
    check_password(password)?;
    let ak = new_account_key()?;
    let vk = new_vault_key()?;
    let recovery = new_recovery_key()?;
    let header = MasterHeader::new(params)?;
    let (account_id, vault_id, device_id) = (random_id()?, random_id()?, random_id()?);
    let seed = Key::random()?;
    let meta = Meta {
        shared: Shared {
            account_id,
            kdf: [params.m_kib(), params.t(), params.p()],
            salt: b64(&header.salt),
            pw_norm: PW_NORM,
            master_wrapper: b64(&wrap_account_key(
                &ak,
                &Wrapper::Master {
                    password,
                    header: &header,
                },
            )?),
            recovery_wrapper: b64(&wrap_account_key(&ak, &Wrapper::Recovery(&recovery))?),
            ak_gen: 0,
            vaults: vec![VaultMeta {
                key_gen: 0,
                wrapped_key: b64(&wrap_vault_key(&ak, 0, vault_id.as_bytes(), 0, &vk)?),
                old: Vec::new(),
                name: String::new(),
                id: vault_id,
            }],
        },
        device_seed: b64(&seal(&ak, 0, &seed_ctx(&device_id), seed.expose())?),
        device_id,
        relay_url: None,
        attested: None,
        attested_vaults: 0,
        acct_published: None,
        device_wrapper: None,
    };
    let code = encode_recovery_key(&recovery);
    Ok((
        Setup {
            store: Some(store),
            meta,
            recovery,
            password: Zeroizing::new(password.to_owned()),
        },
        code,
    ))
}

impl Setup {
    /// Finish setup if `typed` is the recovery key shown earlier; returns the unlocked account.
    pub fn confirm(&mut self, typed: &str, now_ms: u64) -> Result<Account, AccountError> {
        if !verify_retyped(&self.recovery, typed) {
            return Err(AccountError::RecoveryMismatch);
        }
        let store = self.store.take().ok_or(AccountError::Format)?;
        save_meta(&store, &self.meta)?;
        let mut acct = Account::from_parts(store, self.meta.clone())?;
        acct.unlock(&self.password, now_ms)?;
        Ok(acct)
    }
}

/// A pulled record replaces local data only if it authenticates under one of our keys with its
/// id, vault, hlc and tombstone flag intact (SR-5, SR-9). Records that are authentic but
/// unreadable by this build (newer schema) are kept, not treated as tampering.
pub fn verify_record(session: &Session, rec: &Record) -> Verdict {
    match session.open_record(rec) {
        // sealed under a key newer than ours: a rotation we have not received yet
        Err(SessionError::UnknownKeyGen(g))
            if session.key_gen(&rec.vault).is_ok_and(|cur| g > cur) =>
        {
            Verdict::Defer
        }
        // a vault we have not been told of yet (#130): its grant is fetched, then we pull again
        Err(SessionError::NoSuchVault) => Verdict::Defer,
        Err(
            SessionError::Vault(core_vault::VaultError::Crypto)
            | SessionError::UnknownKeyGen(_)
            | SessionError::Locked,
        ) => Verdict::Reject,
        _ => Verdict::Accept,
    }
}

/// An unpushed local edit meeting a remote copy is merged field by field (#40). A copy this
/// build cannot read (newer schema) falls back to whole-record newest-wins. Public so the
/// convergence simulation (#42) runs exactly what [`Account::sync`] runs.
pub fn merge_records(
    session: &Session,
    local: &Record,
    remote: &Record,
    fresh: &str,
) -> Result<Resolution, SyncError> {
    let (Ok(lp), Ok(rp)) = (session.open_record(local), session.open_record(remote)) else {
        return lww(local, remote, fresh);
    };
    let l = Side {
        hlc: &local.hlc,
        tombstone: local.tombstone,
        payload: &lp,
    };
    let r = Side {
        hlc: &remote.hlc,
        tombstone: remote.tombstone,
        payload: &rp,
    };
    match merge(&l, &r) {
        Merged::Local => Ok(Resolution::Keep),
        Merged::Remote => Ok(Resolution::Take),
        // a seal failure is an error, never a reason to drop the local edit
        Merged::New { payload, tombstone } => session
            .seal_record(&local.vault, &local.id, fresh, tombstone, &payload)
            .map(Resolution::Write)
            .map_err(|_| SyncError::Crypto),
    }
}

fn save_meta(store: &Store, meta: &Meta) -> Result<(), AccountError> {
    store.meta_set(
        META_KEY,
        &serde_json::to_vec(meta).map_err(|_| AccountError::Format)?,
    )?;
    Ok(())
}

/// Summary row for the item list: never contains secrets.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ItemSummary {
    pub id: String,
    pub item_type: ItemType,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: u64,
    pub favorite: bool,
    /// Full folder name, `""` for none; the UI nests on `/`.
    pub folder: String,
    pub tags: Vec<String>,
}

/// A login's identity and where it may be used: never contains secrets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub title: String,
    pub username: String,
    /// `(url, match mode)`; the mode is `None` for the default.
    pub urls: Vec<(String, Option<String>)>,
    /// The login holds a TOTP this build can compute (not HOTP, not `steam://`).
    pub totp: bool,
}

/// The current code of a login's TOTP and how long it is good for.
pub struct TotpCode {
    pub code: Zeroizing<String>,
    /// Seconds until the next code.
    pub remaining: u32,
    pub period: u32,
}

/// Full login for the detail and edit views.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginFields {
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
}

impl core::fmt::Debug for LoginFields {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoginFields")
            .field("title", &self.title)
            .finish_non_exhaustive()
    }
}

/// A stored TOTP this build can compute: a time-based one that parses.
fn totp_of(stored: Option<&str>) -> Option<(Otp, u32)> {
    let o = Otp::parse(stored?).ok()?;
    match o.kind {
        Kind::Totp { period } => Some((o, period)),
        Kind::Hotp { .. } => None,
    }
}

fn login_fields(d: Item) -> LoginFields {
    LoginFields {
        title: d.title,
        username: d.username.unwrap_or_default(),
        password: d.password.unwrap_or_default(),
        url: d.urls.first().map(|u| u.url.clone()).unwrap_or_default(),
        notes: d.notes.unwrap_or_default(),
    }
}

/// Outbox size and retry state of the relay sync.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SyncStatus {
    /// Local edits not yet accepted by the relay.
    pub pending: usize,
    /// Set while attempts are paused after a failure; `quota` says the relay is throttling.
    pub backoff: Option<core_sync::backoff::Backoff>,
}

pub struct Account {
    store: Store,
    session: Session,
    clock: Clock,
    meta: Meta,
    device: Option<Device>,
    /// Vault the item commands act on; in memory only, so every unlock starts on the first.
    active: Option<String>,
}

impl Account {
    /// Open an existing account from the store, locked; `None` if the store has none yet.
    pub fn open(store: Store) -> Result<Option<Self>, AccountError> {
        let Some(raw) = store.meta_get(META_KEY)? else {
            return Ok(None);
        };
        let meta: Meta = serde_json::from_slice(&raw).map_err(|_| AccountError::Format)?;
        Ok(Some(Self::from_parts(store, meta)?))
    }

    fn from_parts(store: Store, meta: Meta) -> Result<Self, AccountError> {
        header_of(&meta.shared)?; // refuse stored parameters outside the allowed range
        let clock = Clock::load(&store, node_of(&meta.device_id))?;
        Ok(Self {
            store,
            session: Session::new(),
            clock,
            meta,
            device: None,
            active: None,
        })
    }

    pub fn state(&self) -> State {
        self.session.state()
    }

    pub fn relay_url(&self) -> Option<&str> {
        self.meta.relay_url.as_deref()
    }

    pub fn device_id(&self) -> &str {
        &self.meta.device_id
    }

    pub fn unlock(&mut self, password: &str, now_ms: u64) -> Result<(), AccountError> {
        let s = &self.meta.shared;
        let header = header_of(s)?;
        let vaults = vault_entries(s)?;
        if s.master_wrapper.is_empty() {
            return Err(AccountError::NeedsRecoveryCode);
        }
        let master = unb64(&s.master_wrapper)?;
        self.session.unlock(
            now_ms,
            &self.store,
            &Wrapper::Master {
                password,
                header: &header,
            },
            &master,
            &vaults,
        )?;
        self.load_device()
    }

    /// After the Account Key is open: decrypt this device's relay seed; lock again if it fails.
    fn load_device(&mut self) -> Result<(), AccountError> {
        let seed = unb64(&self.meta.device_seed).and_then(|b| {
            open(
                self.session.account_key()?,
                &seed_ctx(&self.meta.device_id),
                &b,
            )
            .map_err(|_| AccountError::Crypto)
        });
        match seed.and_then(|(_, s)| <[u8; 32]>::try_from(&s[..]).map_err(|_| AccountError::Format))
        {
            Ok(seed) => {
                self.device = Some(Device {
                    id: self.meta.device_id.clone(),
                    seed: Key::from_bytes(seed),
                });
                Ok(())
            }
            Err(e) => {
                self.lock();
                Err(e)
            }
        }
    }

    pub fn lock(&mut self) {
        self.session.lock();
        self.device = None;
        self.active = None;
    }

    /// Record user activity.
    pub fn touch(&mut self, now_ms: u64) {
        self.session.touch(now_ms);
    }

    /// How long without activity locks the account; `None` never. Kept across lock and unlock.
    pub fn set_idle_timeout(&mut self, ms: Option<u64>) {
        self.session.set_idle_timeout(ms);
    }

    /// When the idle timeout will lock this account, if it is unlocked and has one.
    pub fn idle_deadline_ms(&self) -> Option<u64> {
        self.session.idle_deadline_ms()
    }

    /// Auto-lock check; returns whether it locked.
    pub fn tick(&mut self, now_ms: u64) -> bool {
        let locked = self.session.tick(now_ms);
        if locked {
            self.device = None;
            self.active = None;
        }
        locked
    }

    /// Re-authenticate: `password` must open the master wrapper (guards secrets leaving the vault).
    fn check_master_password(&self, password: &str) -> Result<(), AccountError> {
        let header = header_of(&self.meta.shared)?;
        core_keys::unwrap_account_key(
            &unb64(&self.meta.shared.master_wrapper)?,
            &Wrapper::Master {
                password,
                header: &header,
            },
        )
        .map_err(|_| SessionError::Crypto)?;
        Ok(())
    }

    /// The vault the item commands act on: the selected one, else the first.
    fn vault_id(&self) -> Result<&str, AccountError> {
        let vaults = &self.meta.shared.vaults;
        self.active
            .as_deref()
            .and_then(|a| vaults.iter().find(|v| v.id == a))
            .or(vaults.first())
            .map(|v| v.id.as_str())
            .ok_or(AccountError::Format)
    }

    pub fn list_items(&self) -> Result<Vec<ItemSummary>, AccountError> {
        let vault = self.vault_id()?;
        self.session.account_key()?; // Locked is an error, not an empty list
        let mut out = Vec::new();
        for rec in self.store.list(vault)?.iter().filter(|r| !r.tombstone) {
            // A record this build cannot open (newer schema, corruption) is skipped, not fatal.
            if let Ok(p) = self.session.open_record(rec) {
                let d = p.data;
                out.push(ItemSummary {
                    id: rec.id.clone(),
                    item_type: p.item_type,
                    title: d.title,
                    username: d.username.unwrap_or_default(),
                    url: d.urls.first().map(|u| u.url.clone()).unwrap_or_default(),
                    updated_at: d.updated_at,
                    favorite: d.favorite,
                    folder: d.folder.unwrap_or_default(),
                    tags: d.tags,
                });
            }
        }
        out.sort_by_key(|i| i.title.to_lowercase());
        Ok(out)
    }

    /// Every login with all its URLs and their match modes, for a client that decides which logins
    /// belong to a page (autofill). No secrets; a record this build cannot open is skipped.
    pub fn login_candidates(&self) -> Result<Vec<Candidate>, AccountError> {
        let vault = self.vault_id()?;
        self.session.account_key()?;
        Ok(self
            .store
            .list(vault)?
            .iter()
            .filter(|r| !r.tombstone)
            .filter_map(|r| {
                let p = self.session.open_record(r).ok()?;
                // notes, Wi-Fi networks etc. are never offered to a web page
                (p.item_type == ItemType::Login).then_some(())?;
                let d = p.data;
                Some(Candidate {
                    id: r.id.clone(),
                    title: d.title,
                    username: d.username.unwrap_or_default(),
                    totp: totp_of(d.totp.as_deref()).is_some(),
                    urls: d.urls.into_iter().map(|u| (u.url, u.r#match)).collect(),
                })
            })
            .collect())
    }

    /// A live item of the active vault; one in another vault is not found (SR-isolation: the
    /// selected vault is all a client can reach).
    fn live(&self, id: &str) -> Result<Record, AccountError> {
        let vault = self.vault_id()?;
        self.store
            .get(id)?
            .filter(|r| !r.tombstone && r.vault == vault)
            .ok_or(AccountError::NotFound)
    }

    pub fn get_login(&self, id: &str) -> Result<LoginFields, AccountError> {
        Ok(login_fields(
            self.session.open_record(&self.live(id)?)?.data,
        ))
    }

    /// The TOTP code of login `id` at `now_ms`, or `None` if it has none this build can compute.
    pub fn login_totp(&self, id: &str, now_ms: u64) -> Result<Option<TotpCode>, AccountError> {
        let d = self.session.open_record(&self.live(id)?)?.data;
        let now = now_ms / 1000;
        Ok(totp_of(d.totp.as_deref()).and_then(|(o, period)| {
            Some(TotpCode {
                code: o.code(now).ok()?,
                remaining: o.remaining(now)?,
                period,
            })
        }))
    }

    /// Write an edit as `new` (stamping the fields that differ from `old`) or, with `None`,
    /// a tombstone carrying the delete barrier.
    fn write(
        &mut self,
        id: &str,
        old: Option<&Payload>,
        new: Option<Payload>,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let vault = self.vault_id()?.to_owned();
        self.write_in(&vault, id, old, new, now_ms)
    }

    fn write_in(
        &mut self,
        vault: &str,
        id: &str,
        old: Option<&Payload>,
        new: Option<Payload>,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let hlc = self.clock.tick(&self.store, now_ms)?;
        let tombstone = new.is_none();
        let payload = match new {
            Some(mut p) => {
                stamp_changes(old, &mut p, &hlc);
                p
            }
            None => Payload::tombstone(&hlc),
        };
        let rec = self
            .session
            .seal_record(vault, id, &hlc, tombstone, &payload)?;
        self.store.put_local(&rec)?;
        self.session.refresh_index(&self.store, vault)?;
        Ok(())
    }

    /// Create (`id` = `None`) or update a login; unknown fields of an existing item survive.
    pub fn save_login(
        &mut self,
        id: Option<&str>,
        f: &LoginFields,
        now_ms: u64,
    ) -> Result<String, AccountError> {
        let id_was_given = id.is_some();
        let (id, mut payload) = match id {
            Some(id) => (id.to_owned(), self.session.open_record(&self.live(id)?)?),
            None => (
                random_id()?,
                Payload::new_login(Item {
                    created_at: now_ms,
                    ..Item::default()
                }),
            ),
        };
        let old = id_was_given.then(|| payload.clone());
        let d = &mut payload.data;
        let opt = |s: &str| (!s.is_empty()).then(|| s.to_owned());
        d.title = f.title.clone();
        d.username = opt(&f.username);
        d.password = opt(&f.password);
        d.notes = opt(&f.notes);
        d.updated_at = now_ms;
        match (d.urls.first_mut(), opt(&f.url)) {
            (Some(u), Some(new)) => u.url = new,
            (None, Some(new)) => d.urls.push(Url {
                url: new,
                ..Url::default()
            }),
            (Some(_), None) => {
                d.urls.remove(0);
            }
            (None, None) => {}
        }
        self.write(&id, old.as_ref(), Some(payload), now_ms)?;
        Ok(id)
    }

    /// Delete by writing a tombstone, which syncs like any edit.
    pub fn delete_login(&mut self, id: &str, now_ms: u64) -> Result<(), AccountError> {
        self.live(id)?;
        self.write(id, None, None, now_ms)
    }

    fn device(&self) -> Result<&Device, AccountError> {
        self.device
            .as_ref()
            .ok_or(AccountError::Session(SessionError::Locked))
    }

    /// Record the relay URL and register this device as the relay's first one. Everything held
    /// locally is queued for the first sync, so a relay rebuilt from a restored backup (#124,
    /// SR-9) is repopulated; on a new account there is nothing to queue.
    pub fn register_with_relay(
        &mut self,
        transport: &dyn Transport,
        url: &str,
        token: &str,
    ) -> Result<(), AccountError> {
        core_sync::register_first_device(transport, self.device()?, token)?;
        self.store.queue_all()?;
        // a different relay knows nothing of this device's attestation or the account-auth key
        self.meta.attested = None;
        self.meta.acct_published = None;
        self.set_relay_url(url)
    }

    pub fn set_relay_url(&mut self, url: &str) -> Result<(), AccountError> {
        self.meta.relay_url = Some(url.to_owned());
        save_meta(&self.store, &self.meta)
    }

    /// Push local edits and pull remote ones. Needs the account unlocked (for the signing key).
    /// First picks up a key rotation another device made (#44), so what is pulled can be read.
    ///
    /// A network or relay failure pauses further attempts with exponential backoff (#43): until
    /// the pause ends this returns `Sync(Backoff)` without sending anything and local edits stay
    /// queued. [`sync_now`](Self::sync_now) ignores the pause.
    pub fn sync(
        &mut self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<SyncReport, AccountError> {
        if let Some(b) = self.sync_status(now_ms)?.backoff {
            return Err(SyncError::Backoff(b).into());
        }
        self.sync_now(transport, now_ms)
    }

    /// Sync even if a pause is in force (the user asked); a failure restarts the pause.
    pub fn sync_now(
        &mut self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<SyncReport, AccountError> {
        if self.meta.relay_url.is_none() {
            return Err(AccountError::NoRelay);
        }
        self.device()?;
        let out = self.sync_unguarded(transport, now_ms);
        match &out {
            Ok(_) => core_sync::backoff::record(&self.store, now_ms, None)?,
            Err(AccountError::Sync(e)) => core_sync::backoff::record(&self.store, now_ms, Some(e))?,
            Err(_) => {} // local problems (locked, store) are not the relay's fault
        }
        out
    }

    /// What is waiting and whether syncing is paused, for a status line.
    pub fn sync_status(&self, now_ms: u64) -> Result<SyncStatus, AccountError> {
        Ok(SyncStatus {
            pending: self.store.pending()?.len(),
            backoff: core_sync::backoff::status(&self.store, now_ms)?,
        })
    }

    fn sync_unguarded(
        &mut self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<SyncReport, AccountError> {
        if self.meta.relay_url.is_none() {
            return Err(AccountError::NoRelay);
        }
        self.device()?;
        self.receive_rekey(transport, now_ms)?;
        self.receive_vaults(transport, now_ms)?;
        self.publish_account_auth(transport, now_ms)?;
        self.publish_attest(transport, now_ms)?;
        let mut report = match self.pull_push(transport, now_ms) {
            // a rotation or a new vault landed between our check and the pull: fetch it, go again
            Err(AccountError::Sync(SyncError::Deferred)) => {
                self.receive_rekey(transport, now_ms)?;
                self.receive_vaults(transport, now_ms)?;
                self.pull_push(transport, now_ms)?
            }
            r => r?,
        };
        // records still under an old key (ours from before a rotation, or arrived late from a
        // device that had not received it) are re-sealed under the current one and pushed
        if self.reencrypt_stale(now_ms)? > 0 {
            report += self.pull_push(transport, now_ms)?;
        }
        Ok(report)
    }

    fn pull_push(
        &mut self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<SyncReport, AccountError> {
        let device = self.device.as_ref().ok_or(SessionError::Locked)?;
        let session = &self.session;
        let report = core_sync::sync(
            &self.store,
            &mut self.clock,
            transport,
            device,
            now_ms,
            &|rec| verify_record(session, rec),
            &|local, remote, fresh| merge_records(session, local, remote, fresh),
        )?;
        for v in &self.meta.shared.vaults {
            self.session.refresh_index(&self.store, &v.id)?;
        }
        Ok(report)
    }

    /// Keep the relay's account-auth key (#124) at this Account Key generation. A 409 means the
    /// relay is already past it (a rotation this device has not received yet): not an error here.
    fn publish_account_auth(&mut self, t: &dyn Transport, now_ms: u64) -> Result<(), AccountError> {
        let gen_now = self.meta.shared.ak_gen;
        if self.meta.acct_published == Some(gen_now) {
            return Ok(());
        }
        let auth = devices::account_auth(self.session.account_key()?)?;
        match devices::publish_account(t, self.device()?, now_ms, &auth) {
            Ok(()) | Err(SyncError::Status(409)) => {}
            Err(e) => return Err(e.into()),
        }
        self.meta.acct_published = Some(gen_now);
        save_meta(&self.store, &self.meta)
    }

    /// Restored device, no enrolled device left to approve it (#124): register with the relay that
    /// still holds the account by proving possession of the Account Key (the relay compares against
    /// the account-auth key an enrolled device published). A relay that is not this account's, or a
    /// backup older than the last key rotation, is refused. Needs the account unlocked.
    pub fn rejoin_relay(
        &mut self,
        transport: &dyn Transport,
        url: &str,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let auth = devices::account_auth(self.session.account_key()?)?;
        match devices::recover(transport, self.device()?, &auth, now_ms) {
            // already registered: an earlier attempt landed but its answer was lost
            Ok(()) | Err(SyncError::Status(409)) => self.set_relay_url(url),
            Err(e) => Err(e.into()),
        }
    }

    /// Restored device, enrolling through a surviving device (#124): the existing flow, but the
    /// joiner keeps this account's device identity instead of starting an empty account. Send its
    /// request, let the other device approve, then pass the reply to
    /// [`finish_rejoin`](Self::finish_rejoin). Needs the account unlocked. If the backup turns out
    /// to predate a key rotation, the approver has already registered this device and
    /// `finish_rejoin` fails with `StaleBackup`: revoke that orphan device from the approver.
    pub fn rejoin_joiner(&self, code: &str) -> Result<Joiner, AccountError> {
        Ok(Joiner::for_device(code, self.device()?)?)
    }

    /// Finish [`rejoin_joiner`](Self::rejoin_joiner): the reply only has to confirm the keys this
    /// restored account already holds, and a backup older than a key rotation is refused.
    pub fn finish_rejoin(&mut self, payload: &[u8], relay_url: &str) -> Result<(), AccountError> {
        let bundle: Bundle = serde_json::from_slice(payload).map_err(|_| AccountError::Format)?;
        if bundle.shared.account_id != self.meta.shared.account_id {
            return Err(AccountError::Format);
        }
        if bundle.shared.ak_gen != self.meta.shared.ak_gen {
            return Err(AccountError::StaleBackup);
        }
        if !core_crypto::ct_eq(
            &Zeroizing::new(unb64(&bundle.ak)?),
            self.session.account_key()?.expose(),
        ) {
            return Err(AccountError::Format);
        }
        self.set_relay_url(relay_url)
    }

    /// Existing device: open an enrollment session. Returns the code to show.
    pub fn enroll_offer(
        &self,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<(Offer, Zeroizing<String>), AccountError> {
        let code = core_sync::enroll::new_code()?;
        Ok((
            Offer::start(transport, self.device()?, &code, now_ms)?,
            code,
        ))
    }

    pub fn enroll_poll(
        &self,
        offer: &Offer,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<Option<JoinRequest>, AccountError> {
        Ok(offer.poll(transport, self.device()?, now_ms)?)
    }

    /// Existing device: hand the Account Key and wrapped keys to the verified new device.
    pub fn enroll_approve(
        &self,
        offer: &Offer,
        req: &JoinRequest,
        transport: &dyn Transport,
        now_ms: u64,
    ) -> Result<(), AccountError> {
        let ak = self.session.account_key()?;
        let bundle = Bundle {
            shared: self.meta.shared.clone(),
            ak: b64(ak.expose()),
        };
        let payload =
            Zeroizing::new(serde_json::to_vec(&bundle).map_err(|_| AccountError::Format)?);
        Ok(offer.approve(transport, self.device()?, now_ms, req, &payload)?)
    }

    /// New device: persist the account from an enrollment payload. Locked; unlock with the
    /// master password the account already uses.
    pub fn complete_join(
        store: Store,
        joiner: &Joiner,
        payload: &[u8],
        relay_url: &str,
    ) -> Result<Self, AccountError> {
        if store.meta_get(META_KEY)?.is_some() {
            return Err(AccountError::Format); // never overwrite an existing vault
        }
        let bundle: Bundle = serde_json::from_slice(payload).map_err(|_| AccountError::Format)?;
        let ak = Key::from_bytes(
            unb64(&bundle.ak)?
                .try_into()
                .map_err(|_| AccountError::Format)?,
        );
        let device = joiner.device();
        let meta = Meta {
            device_seed: b64(&seal(
                &ak,
                bundle.shared.ak_gen,
                &seed_ctx(&device.id),
                device.seed.expose(),
            )?),
            device_id: device.id,
            relay_url: Some(relay_url.to_owned()),
            attested: None,
            attested_vaults: 0,
            acct_published: None,
            device_wrapper: None,
            shared: bundle.shared,
        };
        header_of(&meta.shared)?;
        save_meta(&store, &meta)?;
        Self::from_parts(store, meta)
    }

    /// Check a recovery code against this account's recovery wrapper (drill, #105 builds on it).
    pub fn recovery_code_opens(&self, code: &str) -> bool {
        let Ok(key) = decode_recovery_key(code) else {
            return false;
        };
        unb64(&self.meta.shared.recovery_wrapper)
            .is_ok_and(|w| core_keys::unwrap_account_key(&w, &Wrapper::Recovery(&key)).is_ok())
    }
}

#[cfg(test)]
mod tests;
