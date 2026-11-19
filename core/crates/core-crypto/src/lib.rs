//! Single wrapper around the RustCrypto crates (ADR 0001, suite 0x01).
//!
//! All crypto in Null Seal goes through here. Nothing custom: XChaCha20-Poly1305,
//! HKDF-SHA256, Argon2id v1.3 and the OS CSPRNG. Failures are one opaque [`Error`]
//! so callers cannot build an oracle out of error variants, and no function returns
//! partial output on failure.

mod asym;
pub use asym::*;
pub mod interop;

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305,
    aead::{Aead, Key as AeadKey, KeyInit, Nonce as AeadNonce, Payload},
};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const KEY_LEN: usize = 32;
pub const NONCE_LEN: usize = 24;
pub const TAG_LEN: usize = 16;
/// Minimum Argon2 salt length we accept (RFC 9106 recommends 16).
pub const MIN_SALT_LEN: usize = 16;

/// Any crypto failure: bad key, tampered data, bad parameters, RNG failure.
#[derive(Debug, PartialEq, Eq)]
pub struct Error;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("crypto operation failed")
    }
}

impl core::error::Error for Error {}

/// 256-bit secret key. Zeroized on drop, redacted in `Debug`, constant-time `==`.
/// Deliberately not `Clone`: copies of key material are made explicitly via [`Key::from_bytes`].
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Fresh key from the OS CSPRNG.
    pub fn random() -> Result<Self, Error> {
        Ok(Self(random_bytes()?))
    }

    pub fn expose(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl PartialEq for Key {
    fn eq(&self, other: &Self) -> bool {
        ct_eq(&self.0, &other.0)
    }
}

impl Eq for Key {}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Key(<redacted>)")
    }
}

/// `N` random bytes from the OS CSPRNG.
pub fn random_bytes<const N: usize>() -> Result<[u8; N], Error> {
    let mut b = [0u8; N];
    getrandom::fill(&mut b).map_err(|_| Error)?;
    Ok(b)
}

/// Constant-time equality (length difference returns false immediately).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// Encrypt with a fresh random 192-bit nonce. Output: `nonce || ciphertext || tag`.
/// There is no way to supply a nonce, so reuse is impossible by construction; 192 random
/// bits make accidental collisions negligible across devices.
pub fn encrypt(key: &Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    encrypt_with_nonce(key, random_bytes()?, aad, plaintext)
}

fn encrypt_with_nonce(
    key: &Key,
    nonce: [u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let ct = cipher(key)
        .encrypt(
            &AeadNonce::<XChaCha20Poly1305>::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error)?;
    Ok([nonce.as_slice(), &ct].concat())
}

/// Inverse of [`encrypt`]. Wrong key, wrong `aad`, truncation or any bit flip returns `Error`.
pub fn decrypt(key: &Key, aad: &[u8], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (nonce, ct) = blob.split_first_chunk::<NONCE_LEN>().ok_or(Error)?;
    let pt = cipher(key)
        .decrypt(
            &AeadNonce::<XChaCha20Poly1305>::from(*nonce),
            Payload { msg: ct, aad },
        )
        .map_err(|_| Error)?;
    Ok(Zeroizing::new(pt))
}

fn cipher(key: &Key) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&AeadKey::<XChaCha20Poly1305>::from(key.0))
}

/// HKDF-SHA256 to a 256-bit key. `info` carries the domain-separation label
/// (e.g. `b"null-seal/v1/kek/master"`).
pub fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<Key, Error> {
    let mut okm = [0u8; KEY_LEN];
    let r = Hkdf::<Sha256>::new(salt, ikm).expand(info, &mut okm);
    let key = Key(okm);
    okm.zeroize();
    r.map_err(|_| Error)?;
    Ok(key)
}

/// SHA-1 of `data`. Exists only because the Pwned Passwords range API is keyed by it (#71);
/// never use it for anything else.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use sha1::Digest;
    sha1::Sha1::digest(data).into()
}

/// Hash for [`hmac`]. SHA-1 exists only for TOTP/HOTP interoperability (RFC 4226 / 6238);
/// never use it for anything else.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HmacAlg {
    Sha1,
    Sha256,
    Sha512,
}

/// HMAC of `msg` under `key` (any length, as RFC 2104 allows).
pub fn hmac(alg: HmacAlg, key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
    use hmac::{Hmac, KeyInit, Mac};
    fn run<M: Mac + KeyInit>(key: &[u8], msg: &[u8]) -> Result<Vec<u8>, Error> {
        let mut m = <M as KeyInit>::new_from_slice(key).map_err(|_| Error)?;
        m.update(msg);
        Ok(m.finalize().into_bytes().to_vec())
    }
    match alg {
        HmacAlg::Sha1 => run::<Hmac<sha1::Sha1>>(key, msg),
        HmacAlg::Sha256 => run::<Hmac<Sha256>>(key, msg),
        HmacAlg::Sha512 => run::<Hmac<sha2::Sha512>>(key, msg),
    }
}

/// Validated Argon2id cost parameters. Bounds from ADR 0001 / #3: the floor stops a
/// downgrade (SR-3), the ceiling stops a crafted envelope from exhausting memory (SR-23).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    m_kib: u32,
    t: u32,
    p: u32,
}

impl KdfParams {
    /// Default for new vaults: 128 MiB, t=3, p=4.
    pub const DEFAULT: Self = Self {
        m_kib: 128 * 1024,
        t: 3,
        p: 4,
    };

    pub fn new(m_kib: u32, t: u32, p: u32) -> Result<Self, Error> {
        let ok = (19 * 1024..=1024 * 1024).contains(&m_kib)
            && (2..=10).contains(&t)
            && (1..=16).contains(&p);
        if ok {
            Ok(Self { m_kib, t, p })
        } else {
            Err(Error)
        }
    }

    pub fn m_kib(&self) -> u32 {
        self.m_kib
    }
    pub fn t(&self) -> u32 {
        self.t
    }
    pub fn p(&self) -> u32 {
        self.p
    }
}

/// Argon2id (v1.3) of the (already NFKC-normalised) password into a 256-bit key.
pub fn argon2id(password: &[u8], salt: &[u8], params: KdfParams) -> Result<Key, Error> {
    if salt.len() < MIN_SALT_LEN {
        return Err(Error);
    }
    let p = Params::new(params.m_kib, params.t, params.p, Some(KEY_LEN)).map_err(|_| Error)?;
    argon2id_raw(password, salt, p)
}

fn argon2id_raw(password: &[u8], salt: &[u8], p: Params) -> Result<Key, Error> {
    let mut out = [0u8; KEY_LEN];
    let r = Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(password, salt, &mut out);
    let key = Key(out);
    out.zeroize();
    r.map_err(|_| Error)?;
    Ok(key)
}

#[cfg(test)]
mod tests;
