//! Read-only interop primitives for opening other password managers' exports (Bitwarden, #68).
//!
//! These exist only because that is the format being read; Null Seal's own data never uses them
//! (ADR 0001: XChaCha20-Poly1305, HKDF, Argon2id). Everything is a published construction from a
//! RustCrypto crate: PBKDF2-HMAC-SHA256, HKDF-Expand, AES-256-CBC with an encrypt-then-MAC tag.

use crate::{Error, HmacAlg, KEY_LEN, Key, ct_eq, hmac};
use aes::cipher::{BlockModeDecrypt, KeyIvInit, block_padding::Pkcs7};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// Ceiling on PBKDF2 rounds from an untrusted file (SR-23). Bitwarden allows up to 2,000,000.
pub const PBKDF2_MAX_ROUNDS: u32 = 10_000_000;
pub const AES_IV_LEN: usize = 16;

/// PBKDF2-HMAC-SHA256 to a 256-bit key.
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], rounds: u32) -> Result<Key, Error> {
    if !(1..=PBKDF2_MAX_ROUNDS).contains(&rounds) {
        return Err(Error);
    }
    let mut out = [0u8; KEY_LEN];
    pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, rounds, &mut out);
    let key = Key(out);
    out.zeroize();
    Ok(key)
}

/// HKDF-Expand (RFC 5869 step 2 only: `prk` is used as is, there is no extract) to 256 bits.
pub fn hkdf_expand(prk: &Key, info: &[u8]) -> Result<Key, Error> {
    let mut okm = [0u8; KEY_LEN];
    let r = Hkdf::<Sha256>::from_prk(prk.expose())
        .map_err(|_| Error)
        .and_then(|h| h.expand(info, &mut okm).map_err(|_| Error));
    let key = Key(okm);
    okm.zeroize();
    r?;
    Ok(key)
}

/// Verify `tag = HMAC-SHA256(mac, iv || ct)` in constant time, and only then decrypt
/// AES-256-CBC/PKCS7. A wrong key, tampering or truncation is one opaque [`Error`].
pub fn aes256_cbc_hmac_decrypt(
    enc: &Key,
    mac: &Key,
    iv: &[u8],
    ct: &[u8],
    tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if iv.len() != AES_IV_LEN {
        return Err(Error);
    }
    let expect = hmac(HmacAlg::Sha256, mac.expose(), &[iv, ct].concat())?;
    if !ct_eq(&expect, tag) {
        return Err(Error);
    }
    cbc::Decryptor::<aes::Aes256>::new_from_slices(enc.expose(), iv)
        .map_err(|_| Error)?
        .decrypt_padded_vec::<Pkcs7>(ct)
        .map(Zeroizing::new)
        .map_err(|_| Error)
}
