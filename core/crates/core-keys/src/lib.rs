//! Key hierarchy from ADR 0001: master / recovery / device wrappers each independently
//! wrap one random Account Key (AK); the AK wraps each random Vault Key (VK).
//!
//! Every wrapped blob is a versioned envelope:
//! `version(1) | suite(1) | key_gen(u32 BE) | nonce(24) | ciphertext | tag(16)`.
//! The first 6 bytes plus a per-blob context are the AEAD associated data, so the
//! version, the generation and the context (KDF parameters, ids) cannot be altered
//! without failing authentication. Unknown versions and suites are rejected.

use core_crypto::{
    KdfParams, Key, argon2id, decrypt, encrypt, hkdf, random_bytes, x25519_public, x25519_shared,
};
use unicode_normalization::UnicodeNormalization;

pub use core_crypto::Error;

mod recovery;
pub use recovery::*;

pub const ENVELOPE_VERSION: u8 = 1;
/// XChaCha20-Poly1305 + HKDF-SHA256 + Argon2id v1.3.
pub const SUITE: u8 = 1;
/// Password normalisation rule: NFKC, then UTF-8, no trimming.
pub const PW_NORM: u8 = 1;
pub const SALT_LEN: usize = 16;
const HEADER_LEN: usize = 6;

/// Public KDF inputs for the master wrapper. Stored in the vault header in the clear and
/// bound into the wrapper's AAD, so lowering them fails authentication (SR-3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MasterHeader {
    pub salt: [u8; SALT_LEN],
    pub params: KdfParams,
    pub pw_norm: u8,
}

impl MasterHeader {
    /// New header with a fresh random salt.
    pub fn new(params: KdfParams) -> Result<Self, Error> {
        Ok(Self {
            salt: random_bytes()?,
            params,
            pw_norm: PW_NORM,
        })
    }
}

/// One way to lock the Account Key. All three open the same AK independently.
pub enum Wrapper<'a> {
    Master {
        password: &'a str,
        header: &'a MasterHeader,
    },
    /// 256-bit random recovery key (encoding for humans lives in #25).
    Recovery(&'a Key),
    /// Random key held in the OS keystore, bound to one device id.
    Device { key: &'a Key, device_id: &'a [u8] },
}

impl Wrapper<'_> {
    /// Returns the key-encryption key and the AAD context for this wrapper.
    fn kek_and_context(&self) -> Result<(Key, Vec<u8>), Error> {
        Ok(match self {
            Wrapper::Master { password, header } => {
                if header.pw_norm != PW_NORM {
                    return Err(Error);
                }
                let pw: String = password.nfkc().collect();
                let stretched = argon2id(pw.as_bytes(), &header.salt, header.params)?;
                let kek = hkdf(stretched.expose(), None, b"null-seal/v1/kek/master")?;
                let p = header.params;
                let ctx = context(&[
                    b"wrap/master",
                    &p.m_kib().to_be_bytes(),
                    &p.t().to_be_bytes(),
                    &p.p().to_be_bytes(),
                    &header.salt,
                    &[header.pw_norm],
                ]);
                (kek, ctx)
            }
            Wrapper::Recovery(k) => (
                hkdf(k.expose(), None, b"null-seal/v1/kek/recovery")?,
                context(&[b"wrap/recovery"]),
            ),
            Wrapper::Device { key, device_id } => (
                hkdf(key.expose(), None, b"null-seal/v1/kek/device")?,
                context(&[b"wrap/device", device_id]),
            ),
        })
    }
}

/// Fresh random Account Key.
pub fn new_account_key() -> Result<Key, Error> {
    Key::random()
}

/// Fresh random Vault Key.
pub fn new_vault_key() -> Result<Key, Error> {
    Key::random()
}

pub fn wrap_account_key(ak: &Key, w: &Wrapper) -> Result<Vec<u8>, Error> {
    let (kek, ctx) = w.kek_and_context()?;
    seal(&kek, 0, &ctx, ak.expose())
}

pub fn unwrap_account_key(blob: &[u8], w: &Wrapper) -> Result<Key, Error> {
    let (kek, ctx) = w.kek_and_context()?;
    key_from(&open(&kek, &ctx, blob)?.1)
}

/// Wrap a Vault Key under the AK. `ak_gen` is the AK generation (stored in the envelope),
/// `vk_gen` the VK generation (bound in the AAD together with `vault_id`).
pub fn wrap_vault_key(
    ak: &Key,
    ak_gen: u32,
    vault_id: &[u8],
    vk_gen: u32,
    vk: &Key,
) -> Result<Vec<u8>, Error> {
    seal(ak, ak_gen, &vault_context(vault_id, vk_gen), vk.expose())
}

pub fn unwrap_vault_key(ak: &Key, vault_id: &[u8], vk_gen: u32, blob: &[u8]) -> Result<Key, Error> {
    key_from(&open(ak, &vault_context(vault_id, vk_gen), blob)?.1)
}

/// Seal `plaintext` to a device's X25519 public key, additionally bound to `binding` (a secret
/// only legitimate senders and receivers hold, e.g. the current Account Key), so neither a
/// relay that knows the public key nor anyone without the secret can forge or read it.
/// Output: `ephemeral public key (32) || envelope`.
pub fn seal_to(
    their_pub: &[u8; 32],
    binding: &[u8],
    ctx: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let eph = Key::random()?;
    let e_pub = x25519_public(&eph);
    let key = x25519_shared(&eph, their_pub, &seal_to_info(&e_pub, their_pub, binding))?;
    Ok([e_pub.as_slice(), &seal(&key, 0, ctx, plaintext)?].concat())
}

/// Inverse of [`seal_to`] for the holder of the X25519 secret and the same `binding`.
pub fn open_from(
    secret: &Key,
    binding: &[u8],
    ctx: &[u8],
    blob: &[u8],
) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    let (e_pub, env) = blob.split_first_chunk::<32>().ok_or(Error)?;
    let key = x25519_shared(
        secret,
        e_pub,
        &seal_to_info(e_pub, &x25519_public(secret), binding),
    )?;
    Ok(open(&key, ctx, env)?.1)
}

fn seal_to_info(e_pub: &[u8; 32], their_pub: &[u8; 32], binding: &[u8]) -> Vec<u8> {
    context(&[b"null-seal/v1/seal-to", e_pub, their_pub, binding])
}

/// Key generation recorded in a (header-valid) envelope, without decrypting it.
pub fn envelope_key_gen(blob: &[u8]) -> Result<u32, Error> {
    Ok(parse_header(blob)?.1)
}

/// Encrypt `plaintext` into an envelope under `key`. Used for records as well as wrappers.
pub fn seal(key: &Key, key_gen: u32, ctx: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = vec![ENVELOPE_VERSION, SUITE];
    out.extend_from_slice(&key_gen.to_be_bytes());
    let body = encrypt(key, &aad(&out, ctx), plaintext)?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Validate the header, authenticate and decrypt. Returns `(key_gen, plaintext)`.
pub fn open(
    key: &Key,
    ctx: &[u8],
    blob: &[u8],
) -> Result<(u32, zeroize::Zeroizing<Vec<u8>>), Error> {
    let (header, key_gen) = parse_header(blob)?;
    Ok((
        key_gen,
        decrypt(key, &aad(header, ctx), &blob[HEADER_LEN..])?,
    ))
}

fn parse_header(blob: &[u8]) -> Result<(&[u8], u32), Error> {
    let (header, _) = blob.split_first_chunk::<HEADER_LEN>().ok_or(Error)?;
    if header[0] != ENVELOPE_VERSION || header[1] != SUITE {
        return Err(Error);
    }
    Ok((
        header,
        u32::from_be_bytes([header[2], header[3], header[4], header[5]]),
    ))
}

fn aad(header: &[u8], ctx: &[u8]) -> Vec<u8> {
    [header, ctx].concat()
}

/// Unambiguous concatenation: each part is prefixed with its u32 BE length.
pub fn context(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in parts {
        out.extend_from_slice(&u32::try_from(p.len()).unwrap_or(u32::MAX).to_be_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn vault_context(vault_id: &[u8], vk_gen: u32) -> Vec<u8> {
    context(&[b"wrap/vault", vault_id, &vk_gen.to_be_bytes()])
}

fn key_from(pt: &[u8]) -> Result<Key, Error> {
    Ok(Key::from_bytes(pt.try_into().map_err(|_| Error)?))
}

#[cfg(test)]
mod tests;
