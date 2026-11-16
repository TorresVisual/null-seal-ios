//! Device identity and key agreement (ADR 0001): Ed25519 signs relay requests, X25519 +
//! HKDF delivers keys to a newly enrolled device. Secrets are plain [`Key`]s (zeroized on
//! drop); public keys and signatures are fixed-size byte arrays.

use crate::{Error, KEY_LEN, Key, ct_eq, hkdf};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const PUBLIC_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

/// Ed25519 public key for a 32-byte secret seed.
pub fn signing_public(seed: &Key) -> [u8; PUBLIC_LEN] {
    SigningKey::from_bytes(seed.expose())
        .verifying_key()
        .to_bytes()
}

/// Deterministic Ed25519 signature (RFC 8032).
pub fn sign(seed: &Key, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
    SigningKey::from_bytes(seed.expose()).sign(msg).to_bytes()
}

/// Strict Ed25519 verification; any malformed key or signature is simply `false`.
pub fn verify(public: &[u8; PUBLIC_LEN], msg: &[u8], sig: &[u8; SIGNATURE_LEN]) -> bool {
    VerifyingKey::from_bytes(public)
        .is_ok_and(|k| k.verify_strict(msg, &Signature::from_bytes(sig)).is_ok())
}

/// X25519 public key for a 32-byte secret.
pub fn x25519_public(secret: &Key) -> [u8; PUBLIC_LEN] {
    x25519_dalek::x25519(*secret.expose(), x25519_dalek::X25519_BASEPOINT_BYTES)
}

/// X25519 Diffie-Hellman, then HKDF-SHA256 over the shared secret with `info` as the
/// domain-separation label. Fails on a low-order peer key (all-zero shared secret).
pub fn x25519_shared(
    secret: &Key,
    their_public: &[u8; PUBLIC_LEN],
    info: &[u8],
) -> Result<Key, Error> {
    let shared = zeroize::Zeroizing::new(x25519_dalek::x25519(*secret.expose(), *their_public));
    if ct_eq(&*shared, &[0u8; KEY_LEN]) {
        return Err(Error);
    }
    hkdf(&*shared, None, info)
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}
