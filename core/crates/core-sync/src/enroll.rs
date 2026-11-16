//! Device enrollment (#34): hand the Account Key (or any payload) from an enrolled device
//! to a new one through the relay without the relay being able to read or forge it.
//!
//! ```text
//!  existing device (Offer)                    relay                  new device (Joiner)
//!   code = 128-bit secret, shown on screen ---- out of band (eyes / QR) ------> typed in
//!   sid  = HKDF(secret)  ---- POST /enroll ---> session (10 min, one use)
//!                                       <--- PUT request {id, ed25519, x25519, MAC(secret)}
//!   verify MAC, then seal payload to the new X25519 key, mixing in the secret
//!   ---- POST approve {ephemeral pub || ciphertext} --> registers the new device
//!                                       ---> GET result (one shot)  --> open payload
//! ```
//!
//! The relay never learns the secret: swapping the new device's keys breaks the MAC, and
//! even a swapped X25519 key could not derive the sealing key, which also binds the secret.
//! The session id is a one-way derivation, so seeing it does not help guess the code.

use crate::{Device, Request, SyncError, Transport, b64, unb64};
use core_crypto::{HmacAlg, Key, ct_eq, hkdf, hmac, random_bytes, x25519_public, x25519_shared};
use core_keys::{context, open, seal};
use serde_json::Value;
use zeroize::Zeroizing;

const SECRET_LEN: usize = 16;

/// A fresh enrollment code to show on the existing device: 32 hex digits in groups of four.
pub fn new_code() -> Result<Zeroizing<String>, SyncError> {
    let secret = random_bytes::<SECRET_LEN>().map_err(|_| SyncError::Crypto)?;
    let flat: String = secret.iter().map(|b| format!("{b:02x}")).collect();
    let grouped: Vec<&str> = (0..flat.len())
        .step_by(4)
        .map(|i| &flat[i..i + 4])
        .collect();
    Ok(Zeroizing::new(grouped.join("-")))
}

fn parse_code(code: &str) -> Result<Zeroizing<[u8; SECRET_LEN]>, SyncError> {
    let digits: String = code
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect::<String>()
        .to_ascii_lowercase();
    if digits.len() != SECRET_LEN * 2 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SyncError::Crypto);
    }
    let mut out = Zeroizing::new([0u8; SECRET_LEN]);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[2 * i..2 * i + 2], 16).map_err(|_| SyncError::Crypto)?;
    }
    Ok(out)
}

fn sid(secret: &[u8]) -> Result<String, SyncError> {
    let k = hkdf(secret, None, b"null-seal/v1/enroll/sid").map_err(|_| SyncError::Crypto)?;
    Ok(crate::hex(&k.expose()[..16]))
}

fn request_mac(
    secret: &[u8],
    sid: &str,
    device_id: &str,
    pubkey: &[u8],
    x_pub: &[u8],
) -> Result<Vec<u8>, SyncError> {
    let key = hkdf(secret, None, b"null-seal/v1/enroll/mac").map_err(|_| SyncError::Crypto)?;
    let msg = context(&[
        b"enroll/request",
        sid.as_bytes(),
        device_id.as_bytes(),
        pubkey,
        x_pub,
    ]);
    hmac(HmacAlg::Sha256, key.expose(), &msg).map_err(|_| SyncError::Crypto)
}

fn seal_key(
    secret: &[u8],
    mine: &Key,
    their_pub: &[u8; 32],
    e_pub: &[u8; 32],
    n_pub: &[u8; 32],
) -> Result<Key, SyncError> {
    let info = context(&[b"null-seal/v1/enroll/seal", secret, e_pub, n_pub]);
    x25519_shared(mine, their_pub, &info).map_err(|_| SyncError::Crypto)
}

fn payload_ctx(sid: &str, device_id: &str) -> Vec<u8> {
    context(&[b"enroll/payload", sid.as_bytes(), device_id.as_bytes()])
}

fn key32(v: &Value, field: &str) -> Result<[u8; 32], SyncError> {
    v[field]
        .as_str()
        .and_then(unb64)
        .and_then(|b| b.try_into().ok())
        .ok_or(SyncError::Protocol("enrollment key"))
}

fn plain(method: &'static str, path: String, body: Vec<u8>) -> Request {
    Request {
        method,
        path,
        headers: Vec::new(),
        body,
    }
}

/// What the new device asked for, MAC verified.
pub struct JoinRequest {
    pub device_id: String,
    pub pubkey: [u8; 32],
    x_pub: [u8; 32],
}

/// Existing device side.
pub struct Offer {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    sid: String,
}

impl Offer {
    /// Open the session on the relay for a code from [`new_code`].
    pub fn start(
        t: &dyn Transport,
        me: &Device,
        code: &str,
        now_ms: u64,
    ) -> Result<Self, SyncError> {
        let secret = parse_code(code)?;
        let sid = sid(&*secret)?;
        let body = serde_json::json!({ "sid": sid }).to_string().into_bytes();
        let res = t.send(&me.sign_request("POST", "/v1/enroll", body, now_ms))?;
        if res.status != 201 {
            return Err(SyncError::Status(res.status));
        }
        Ok(Self { secret, sid })
    }

    /// The new device's request, or `None` while it has not arrived. A request whose MAC
    /// does not verify (someone without the code, or a tampering relay) is an error.
    pub fn poll(
        &self,
        t: &dyn Transport,
        me: &Device,
        now_ms: u64,
    ) -> Result<Option<JoinRequest>, SyncError> {
        let path = format!("/v1/enroll/{}", self.sid);
        let res = t.send(&me.sign_request("GET", &path, Vec::new(), now_ms))?;
        match res.status {
            202 => return Ok(None),
            200 => {}
            s => return Err(SyncError::Status(s)),
        }
        let v: Value =
            serde_json::from_slice(&res.body).map_err(|_| SyncError::Protocol("enroll request"))?;
        let device_id = v["device_id"]
            .as_str()
            .ok_or(SyncError::Protocol("device_id"))?
            .to_owned();
        let (pubkey, x_pub) = (key32(&v, "pubkey")?, key32(&v, "x_pub")?);
        let mac = v["mac"]
            .as_str()
            .and_then(unb64)
            .ok_or(SyncError::Protocol("mac"))?;
        let want = request_mac(&*self.secret, &self.sid, &device_id, &pubkey, &x_pub)?;
        if !ct_eq(&mac, &want) {
            return Err(SyncError::Crypto);
        }
        Ok(Some(JoinRequest {
            device_id,
            pubkey,
            x_pub,
        }))
    }

    /// Seal `payload` to the verified new device and register it on the relay.
    pub fn approve(
        &self,
        t: &dyn Transport,
        me: &Device,
        now_ms: u64,
        req: &JoinRequest,
        payload: &[u8],
    ) -> Result<(), SyncError> {
        let eph = Key::random().map_err(|_| SyncError::Crypto)?;
        let e_pub = x25519_public(&eph);
        let key = seal_key(&*self.secret, &eph, &req.x_pub, &e_pub, &req.x_pub)?;
        let ct = seal(&key, 0, &payload_ctx(&self.sid, &req.device_id), payload)
            .map_err(|_| SyncError::Crypto)?;
        let body = serde_json::json!({ "ct": b64(&[e_pub.as_slice(), &ct].concat()) })
            .to_string()
            .into_bytes();
        let path = format!("/v1/enroll/{}/approve", self.sid);
        match t
            .send(&me.sign_request("POST", &path, body, now_ms))?
            .status
        {
            200 => Ok(()),
            s => Err(SyncError::Status(s)),
        }
    }
}

/// New device side. Holds the fresh identity until enrollment completes.
pub struct Joiner {
    secret: Zeroizing<[u8; SECRET_LEN]>,
    sid: String,
    device_id: String,
    seed: Key,
    x_secret: Key,
}

impl Joiner {
    pub fn new(code: &str) -> Result<Self, SyncError> {
        let secret = parse_code(code)?;
        let sid = sid(&*secret)?;
        let id: [u8; 16] = random_bytes().map_err(|_| SyncError::Crypto)?;
        Ok(Self {
            secret,
            sid,
            device_id: crate::hex(&id),
            seed: Key::random().map_err(|_| SyncError::Crypto)?,
            x_secret: Key::random().map_err(|_| SyncError::Crypto)?,
        })
    }

    /// A joiner that keeps an existing device identity, for a device restored from a backup that
    /// re-attaches to its relay through a surviving device (#124).
    pub fn for_device(code: &str, device: &Device) -> Result<Self, SyncError> {
        let secret = parse_code(code)?;
        Ok(Self {
            sid: sid(&*secret)?,
            secret,
            device_id: device.id.clone(),
            seed: Key::from_bytes(*device.seed.expose()),
            x_secret: Key::random().map_err(|_| SyncError::Crypto)?,
        })
    }

    /// This device's relay identity (valid once the existing device approves).
    pub fn device(&self) -> Device {
        Device {
            id: self.device_id.clone(),
            seed: Key::from_bytes(*self.seed.expose()),
        }
    }

    /// Post the new device's public keys with a MAC keyed by the code.
    pub fn send_request(&self, t: &dyn Transport) -> Result<(), SyncError> {
        let (pubkey, x_pub) = (self.device().public_key(), x25519_public(&self.x_secret));
        let mac = request_mac(&*self.secret, &self.sid, &self.device_id, &pubkey, &x_pub)?;
        let body = serde_json::json!({
            "device_id": self.device_id, "pubkey": b64(&pubkey), "x_pub": b64(&x_pub), "mac": b64(&mac),
        })
        .to_string()
        .into_bytes();
        let res = t.send(&plain(
            "PUT",
            format!("/v1/enroll/{}/request", self.sid),
            body,
        ))?;
        match res.status {
            204 => Ok(()),
            s => Err(SyncError::Status(s)),
        }
    }

    /// The sealed payload once approved (one shot: the relay forgets it after this read),
    /// or `None` while pending.
    pub fn poll_result(&self, t: &dyn Transport) -> Result<Option<Zeroizing<Vec<u8>>>, SyncError> {
        let res = t.send(&plain(
            "GET",
            format!("/v1/enroll/{}/result", self.sid),
            Vec::new(),
        ))?;
        match res.status {
            202 => return Ok(None),
            200 => {}
            s => return Err(SyncError::Status(s)),
        }
        let v: Value =
            serde_json::from_slice(&res.body).map_err(|_| SyncError::Protocol("enroll result"))?;
        let blob = v["ct"]
            .as_str()
            .and_then(unb64)
            .ok_or(SyncError::Protocol("ct"))?;
        let (e_pub, ct) = blob.split_first_chunk::<32>().ok_or(SyncError::Crypto)?;
        let n_pub = x25519_public(&self.x_secret);
        let key = seal_key(&*self.secret, &self.x_secret, e_pub, e_pub, &n_pub)?;
        let (_, pt) = open(&key, &payload_ctx(&self.sid, &self.device_id), ct)
            .map_err(|_| SyncError::Crypto)?;
        Ok(Some(pt))
    }
}
