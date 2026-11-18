//! Device registry and key-rotation calls (#44). Transport only: the keys and sealing live in
//! `seal-core`, the relay just stores opaque blobs next to each device row (SR-1).

use crate::client::call;
use crate::{Device, Request, SyncError, Transport, b64, unb64};
use core_crypto::{Key, hkdf, sign, signing_public};
use serde::Deserialize;

/// One row of the relay's device table. `attest` is the opaque blob the device published about
/// itself; the relay's own claim (`pubkey`) is only trusted once `attest` vouches for it.
#[derive(Debug)]
pub struct RemoteDevice {
    pub id: String,
    pub pubkey: [u8; 32],
    pub created_at: u64,
    /// When the relay last saw a signed request from it (relay clock, Unix ms, coarse); `None`
    /// before its first one, or from a relay that predates the column.
    pub last_seen: Option<u64>,
    pub attest: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct Row {
    id: String,
    pubkey: String,
    created_at: u64,
    #[serde(default)]
    last_seen: Option<u64>,
    attest: Option<String>,
}

fn json_body(v: serde_json::Value) -> Vec<u8> {
    v.to_string().into_bytes()
}

pub fn list(t: &dyn Transport, me: &Device, now_ms: u64) -> Result<Vec<RemoteDevice>, SyncError> {
    #[derive(Deserialize)]
    struct Resp {
        devices: Vec<Row>,
    }
    let r: Resp = serde_json::from_slice(&call(t, me, now_ms, "GET", "/v1/devices", Vec::new())?)
        .map_err(|_| SyncError::Protocol("device list"))?;
    r.devices
        .into_iter()
        .map(|d| {
            Ok(RemoteDevice {
                pubkey: unb64(&d.pubkey)
                    .and_then(|b| b.try_into().ok())
                    .ok_or(SyncError::Protocol("device key"))?,
                attest: d.attest.and_then(|a| unb64(&a)),
                id: d.id,
                created_at: d.created_at,
                last_seen: d.last_seen,
            })
        })
        .collect()
}

/// Publish this device's attestation (sealed under the Account Key by the caller).
pub fn publish_attest(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
    attest: &[u8],
) -> Result<(), SyncError> {
    let body = json_body(serde_json::json!({ "attest": b64(attest) }));
    call(t, me, now_ms, "PUT", "/v1/devices/me", body).map(drop)
}

/// The signing key that proves possession of the Account Key to the relay (#124). Derived, so any
/// device that holds the Account Key (including one restored from a backup) has it, and the relay
/// only ever sees the public half.
pub fn account_auth(ak: &Key) -> Result<Key, SyncError> {
    hkdf(ak.expose(), None, b"null-seal/v1/account/auth").map_err(|_| SyncError::Crypto)
}

/// An account-auth key as the relay stores it: the public half only.
fn account_json(auth: &Key) -> serde_json::Value {
    serde_json::json!({ "pubkey": b64(&signing_public(auth)) })
}

/// Tell the relay this account's auth key. Create-only: the same key is a no-op, and a different
/// one is refused (409), since only a rotation may replace it.
pub fn publish_account(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
    auth: &Key,
) -> Result<(), SyncError> {
    let body = json_body(account_json(auth));
    call(t, me, now_ms, "PUT", "/v1/account", body).map(drop)
}

/// Register `me` on a relay that still holds this account but none of whose devices we have, by
/// signing with the account-auth key instead of a device key. The relay refuses (401) unless it
/// holds the matching public key, so a relay that is not this account's never accepts the device.
pub fn recover(t: &dyn Transport, me: &Device, auth: &Key, now_ms: u64) -> Result<(), SyncError> {
    let pubkey = b64(&me.public_key());
    let msg = [
        "null-seal-v1",
        "recover",
        &me.id,
        &pubkey,
        &now_ms.to_string(),
    ]
    .join("\n");
    let body = json_body(serde_json::json!({
        "device_id": me.id, "pubkey": pubkey, "ts": now_ms, "sig": b64(&sign(auth, msg.as_bytes())),
    }));
    let req = Request {
        method: "POST",
        path: "/v1/devices/recover".into(),
        headers: Vec::new(),
        body,
    };
    match t.send(&req)?.status {
        201 => Ok(()),
        s => Err(SyncError::Status(s)),
    }
}

/// Atomically remove `revoke` from the relay and store one sealed key bundle per remaining
/// device. The relay refuses (409) unless `revoke` plus the `rekey` targets are exactly the
/// registered devices, so a device enrolled meanwhile is never left without keys. The new
/// account-auth key replaces the old one in the same step, so the retired Account Key stops
/// working as a way back in at the moment its holders are revoked.
pub fn rotate(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
    revoke: &[String],
    rekey: &[(String, Vec<u8>)],
    account: &Key,
) -> Result<(), SyncError> {
    let rekey: serde_json::Map<_, _> = rekey
        .iter()
        .map(|(id, blob)| (id.clone(), b64(blob).into()))
        .collect();
    let body = json_body(serde_json::json!({
        "revoke": revoke, "rekey": rekey, "account": account_json(account),
    }));
    call(t, me, now_ms, "POST", "/v1/rotate", body).map(drop)
}

/// The key bundle waiting for this device, if a rotation happened since it last synced.
pub fn fetch_rekey(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
) -> Result<Option<Vec<u8>>, SyncError> {
    #[derive(Deserialize)]
    struct Resp {
        rekey: Option<String>,
    }
    let r: Resp = serde_json::from_slice(&call(t, me, now_ms, "GET", "/v1/rekey", Vec::new())?)
        .map_err(|_| SyncError::Protocol("rekey response"))?;
    r.rekey
        .map(|s| unb64(&s).ok_or(SyncError::Protocol("rekey blob")))
        .transpose()
}

/// Tell the relay the bundle was applied, so it no longer holds a copy of the keys.
pub fn clear_rekey(t: &dyn Transport, me: &Device, now_ms: u64) -> Result<(), SyncError> {
    call(t, me, now_ms, "DELETE", "/v1/rekey", Vec::new()).map(drop)
}
