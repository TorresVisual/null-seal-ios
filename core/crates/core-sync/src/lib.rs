//! Sync client (ADR 0001, relay API in `relay/README.md`).
//!
//! Transport-agnostic: the core has no HTTP stack, so the platform supplies a [`Transport`]
//! (desktop: `seal-http`; iOS: URLSession) and passes wall-clock milliseconds in. Sync moves
//! only ciphertext, so it needs no unlocked session; the only secret it touches is the
//! device's Ed25519 seed, used to sign requests (SR-8).

use base64::{Engine, engine::general_purpose::STANDARD as B64};
use core_crypto::{Key, sha256, sign, signing_public};

pub mod backoff;
pub mod backup;
pub mod client;
pub mod devices;
pub mod enroll;
pub mod hlc;
#[cfg(any(test, feature = "mock"))]
pub mod mock;
#[cfg(test)]
mod tests;

pub use client::{Merge, Resolution, SyncReport, Verdict, lww, sync};
pub use hlc::Clock;

/// An HTTP request the transport sends to `<relay base url><path>`.
#[derive(Debug)]
pub struct Request {
    pub method: &'static str,
    /// Path and query exactly as signed, e.g. `/v1/pull?cursor=0`.
    pub path: String,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: Vec<u8>,
}

/// The network failed (not a relay error status): no connection, timeout, TLS.
#[derive(Debug)]
pub struct TransportError(pub String);

pub trait Transport {
    fn send(&self, req: &Request) -> Result<Response, TransportError>;
}

#[derive(Debug)]
pub enum SyncError {
    Transport(String),
    /// The relay refused the request (401: this device is not enrolled or the clock is off).
    Status(u16),
    /// The relay answered something the protocol does not allow.
    Protocol(&'static str),
    Store(core_store::StoreError),
    Clock(hlc::ClockError),
    Crypto,
    /// Pending edits remain after the retry budget; run sync again.
    Unsettled,
    /// A pulled record is sealed under a key this device does not have yet (see [`Verdict::Defer`]).
    Deferred,
    /// A recent failure paused syncing; nothing was sent. See [`backoff`].
    Backoff(backoff::Backoff),
}

impl From<TransportError> for SyncError {
    fn from(e: TransportError) -> Self {
        Self::Transport(e.0)
    }
}
impl From<core_store::StoreError> for SyncError {
    fn from(e: core_store::StoreError) -> Self {
        Self::Store(e)
    }
}
impl From<hlc::ClockError> for SyncError {
    fn from(e: hlc::ClockError) -> Self {
        Self::Clock(e)
    }
}

impl core::fmt::Display for SyncError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Transport(m) => write!(f, "network error: {m}"),
            Self::Status(s) => write!(f, "relay refused the request (HTTP {s})"),
            Self::Protocol(m) => write!(f, "unexpected relay response: {m}"),
            Self::Store(e) => e.fmt(f),
            Self::Clock(e) => e.fmt(f),
            Self::Crypto => f.write_str("crypto error"),
            Self::Unsettled => f.write_str("sync did not settle, try again"),
            Self::Deferred => f.write_str("records use a newer key than this device holds"),
            Self::Backoff(b) if b.quota => {
                write!(
                    f,
                    "the relay is limiting requests; next try at {} ms",
                    b.retry_at_ms
                )
            }
            Self::Backoff(b) => write!(
                f,
                "sync is paused after {} failures; next try at {} ms",
                b.failures, b.retry_at_ms
            ),
        }
    }
}

impl core::error::Error for SyncError {}

/// This device's relay identity: an id and the Ed25519 seed that signs requests.
pub struct Device {
    pub id: String,
    pub seed: Key,
}

impl Device {
    pub fn public_key(&self) -> [u8; 32] {
        signing_public(&self.seed)
    }

    /// X25519 secret that receives key rotations (#44), derived from the seed so no extra
    /// secret is stored and every existing device already has one.
    pub fn x_secret(&self) -> Result<Key, SyncError> {
        core_crypto::hkdf(self.seed.expose(), None, b"null-seal/v1/device/x25519")
            .map_err(|_| SyncError::Crypto)
    }

    pub fn x_public(&self) -> Result<[u8; 32], SyncError> {
        Ok(core_crypto::x25519_public(&self.x_secret()?))
    }

    /// Build a signed request: `x-sig` covers
    /// `null-seal-v1\n{method}\n{path}\n{ts}\n{sha256hex(body)}`.
    pub fn sign_request(
        &self,
        method: &'static str,
        path: &str,
        body: Vec<u8>,
        now_ms: u64,
    ) -> Request {
        let msg = format!(
            "null-seal-v1\n{method}\n{path}\n{now_ms}\n{}",
            hex(&sha256(&body))
        );
        Request {
            method,
            path: path.to_owned(),
            headers: vec![
                ("x-device", self.id.clone()),
                ("x-ts", now_ms.to_string()),
                ("x-sig", B64.encode(sign(&self.seed, msg.as_bytes()))),
            ],
            body,
        }
    }
}

/// First-device registration on a fresh relay; `token` is the deploy-time setup token.
pub fn register_first_device(
    transport: &dyn Transport,
    device: &Device,
    token: &str,
) -> Result<(), SyncError> {
    let body = serde_json::json!({
        "device_id": device.id,
        "pubkey": B64.encode(device.public_key()),
    });
    let req = Request {
        method: "POST",
        path: "/v1/bootstrap".into(),
        headers: vec![("x-setup-token", token.to_owned())],
        body: body.to_string().into_bytes(),
    };
    match transport.send(&req)?.status {
        201 => Ok(()),
        s => Err(SyncError::Status(s)),
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    use core::fmt::Write;
    b.iter().fold(String::new(), |mut s, x| {
        let _ = write!(s, "{x:02x}");
        s
    })
}

pub(crate) fn b64(b: &[u8]) -> String {
    B64.encode(b)
}

pub(crate) fn unb64(s: &str) -> Option<Vec<u8>> {
    B64.decode(s).ok()
}
