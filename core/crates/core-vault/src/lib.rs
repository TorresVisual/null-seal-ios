//! Vault items (ADR 0001, "Plaintext payload"): a versioned JSON payload, padded to a
//! multiple of 256 bytes and sealed under the Vault Key with the vault id, record id,
//! revision (HLC) and tombstone flag bound as associated data (SR-5, SR-6).
//!
//! Forward compatibility: every struct keeps unknown keys (`#[serde(flatten)]`), so a
//! client that does not know a newer field still writes it back untouched. A payload
//! whose schema version is newer than [`SCHEMA_VERSION`] is refused instead, because
//! rewriting it could silently drop data this client cannot see.

pub mod merge;

use core_crypto::Key;
use core_keys::{context, open, seal};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Payload schema version written by this build, independent of the envelope version.
pub const SCHEMA_VERSION: u32 = 1;
/// Plaintext is padded to a multiple of this many bytes before encryption.
pub const PAD_BLOCK: usize = 256;

#[derive(Debug, PartialEq, Eq)]
pub enum VaultError {
    /// Authentication failed: wrong key, or key/id/revision/tombstone/bytes altered.
    Crypto,
    /// Authentic but not parseable: bad padding, bad JSON, unknown kind or item type.
    Format,
    /// Authentic payload written by a newer schema; refuse rather than rewrite lossy.
    Version(u32),
}

impl core::fmt::Display for VaultError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto => f.write_str("record failed authentication"),
            Self::Format => f.write_str("record payload is malformed"),
            Self::Version(v) => write!(f, "record uses unsupported schema version {v}"),
        }
    }
}

impl core::error::Error for VaultError {}

/// Record kinds. Only items for now; folders and vault metadata join later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Item,
}

/// Item types. An unknown type fails to parse (`Format`): the record stays untouched
/// on the relay and is not shown, rather than being edited blind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Login,
    /// Secure note: `title` and `notes` only.
    Note,
    /// Wi-Fi network: `ssid`, `wifi_security`, `password`.
    Wifi,
    /// Software license: `license_key`, `licensed_to`.
    License,
    /// One-time recovery codes of an account: `codes`.
    RecoveryCodes,
    /// Authenticator entry: `totp` (an `otpauth://` URI or bare base32 secret, as on a login).
    Totp,
    /// SSH key: `private_key` (an unencrypted OpenSSH file; public key and fingerprint derive from it).
    SshKey,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Payload {
    /// Schema version; always written, never assumed.
    pub v: u32,
    pub kind: Kind,
    #[serde(rename = "type")]
    pub item_type: ItemType,
    /// Per-field HLC stamps for the merge engine (#40).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub fields_hlc: BTreeMap<String, String>,
    pub data: Item,
    /// Prior versions of `data`, newest first, at most [`HISTORY_MAX`] (#41). Merged as a union.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub history: Vec<Version>,
    /// Opaque bag for source or future fields no struct models (imports, #67).
    #[serde(default, skip_serializing_if = "Map::is_empty")]
    pub extras: Map<String, Value>,
    #[serde(flatten)]
    pub unknown: Map<String, Value>,
}

impl Payload {
    pub fn new_login(data: Item) -> Self {
        Self::new(ItemType::Login, data)
    }

    pub fn new(item_type: ItemType, data: Item) -> Self {
        Self {
            v: SCHEMA_VERSION,
            kind: Kind::Item,
            item_type,
            fields_hlc: BTreeMap::new(),
            data,
            history: Vec::new(),
            extras: Map::new(),
            unknown: Map::new(),
        }
    }

    /// Payload of a tombstone record: empty, carrying only the delete barrier (see [`merge`]).
    pub fn tombstone(hlc: &str) -> Self {
        let mut p = Self::new_login(Item::default());
        p.fields_hlc
            .insert(merge::DELETED.to_owned(), hlc.to_owned());
        p
    }
}

/// How many prior versions an item keeps (retention policy; oldest are dropped first).
pub const HISTORY_MAX: usize = 10;

/// An item as it was before an edit.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    /// HLC of the edit that replaced this version; identifies it and orders the history.
    pub at: String,
    pub data: Item,
}

/// Item fields: the common set plus the login fields. Timestamps are Unix milliseconds.
/// Other item types add their own optional fields here (additive, never a version bump).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    #[serde(default)]
    pub title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(default)]
    pub favorite: bool,
    /// Full folder name; the UI may nest on `/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default)]
    pub reprompt: bool,
    #[serde(default)]
    pub created_at: u64,
    #[serde(default)]
    pub updated_at: u64,
    /// Set = in trash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<u64>,

    // login
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Raw string kept verbatim: `otpauth://`, bare base32 or `steam://`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totp: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub urls: Vec<Url>,

    // wifi (the network password is `password`)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssid: Option<String>,
    /// Free text (`WPA2`, `WPA3`, `open`, ...) so a newer mode survives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wifi_security: Option<String>,

    // license
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub licensed_to: Option<String>,

    // recovery codes: one code per element. A concurrent edit of two devices keeps the newer
    // list whole (the merge treats it as one register); the older one stays in the history.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub codes: Vec<String>,

    // ssh key
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    #[serde(flatten)]
    pub unknown: Map<String, Value>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Url {
    pub url: String,
    /// `domain|host|starts_with|exact|regex|never`; `None` = use the app default, which is
    /// distinct from `domain`. A string, not an enum, so a newer match mode survives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#match: Option<String>,
    #[serde(flatten)]
    pub unknown: Map<String, Value>,
}

/// What a record's ciphertext is bound to. Changing any field makes `open_item` fail.
#[derive(Clone, Copy, Debug)]
pub struct RecordContext<'a> {
    pub vault_id: &'a [u8],
    pub record_id: &'a [u8],
    /// Revision: the record's 24-hex-char HLC.
    pub hlc: &'a str,
    pub tombstone: bool,
}

impl RecordContext<'_> {
    fn aad(&self) -> Vec<u8> {
        context(&[
            b"record",
            self.vault_id,
            self.record_id,
            self.hlc.as_bytes(),
            &[u8::from(self.tombstone)],
        ])
    }
}

/// Serialize, pad (ISO/IEC 7816-4) and seal under `vk` at generation `key_gen`.
pub fn seal_item(
    vk: &Key,
    key_gen: u32,
    ctx: &RecordContext,
    payload: &Payload,
) -> Result<Vec<u8>, VaultError> {
    let mut pt = Zeroizing::new(serde_json::to_vec(payload).map_err(|_| VaultError::Format)?);
    pt.push(0x80);
    let padded = pt.len().next_multiple_of(PAD_BLOCK);
    pt.resize(padded, 0);
    seal(vk, key_gen, &ctx.aad(), &pt).map_err(|_| VaultError::Crypto)
}

/// Key generation a record blob was sealed under, read from its envelope header without
/// decrypting (to pick the right key during a rotation).
pub fn blob_key_gen(blob: &[u8]) -> Result<u32, VaultError> {
    core_keys::envelope_key_gen(blob).map_err(|_| VaultError::Crypto)
}

/// Authenticate, unpad and parse. Returns `(key_gen, payload)`; nothing on any failure.
pub fn open_item(vk: &Key, ctx: &RecordContext, blob: &[u8]) -> Result<(u32, Payload), VaultError> {
    let (key_gen, pt) = open(vk, &ctx.aad(), blob).map_err(|_| VaultError::Crypto)?;
    let end = pt.iter().rposition(|&b| b != 0).ok_or(VaultError::Format)?;
    if pt[end] != 0x80 {
        return Err(VaultError::Format);
    }
    // Check the version before the shape: a newer schema may not fit our structs at all.
    let json: Value = serde_json::from_slice(&pt[..end]).map_err(|_| VaultError::Format)?;
    let v = json
        .get("v")
        .and_then(Value::as_u64)
        .ok_or(VaultError::Format)?;
    if v == 0 || v > u64::from(SCHEMA_VERSION) {
        return Err(VaultError::Version(u32::try_from(v).unwrap_or(u32::MAX)));
    }
    let payload = serde_json::from_value(json).map_err(|_| VaultError::Format)?;
    Ok((key_gen, payload))
}

#[cfg(test)]
mod tests;
