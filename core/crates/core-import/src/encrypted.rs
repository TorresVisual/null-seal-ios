//! Password-protected Bitwarden JSON export (#68).
//!
//! Bitwarden derives a master key from the export password (PBKDF2-SHA256 or Argon2id, parameters
//! in the file), stretches it with HKDF-Expand (`enc`, `mac`) and seals both `data` and a
//! validation string as EncString type 2 (`2.iv|ct|mac`, AES-256-CBC + HMAC-SHA256). The
//! plaintext of `data` is the unencrypted export, so [`bitwarden_json`] maps it from there.

use crate::{Import, ImportError, MAX_INPUT, bitwarden_json};
use base64::{Engine, engine::general_purpose::STANDARD};
use core_crypto::{KdfParams, Key, argon2id, interop, sha256};
use serde::Deserialize;
use zeroize::Zeroizing;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Envelope {
    encrypted: bool,
    password_protected: bool,
    salt: String,
    /// 0 = PBKDF2-SHA256, 1 = Argon2id.
    kdf_type: u8,
    kdf_iterations: u32,
    /// Argon2id only, in MiB.
    kdf_memory: Option<u32>,
    kdf_parallelism: Option<u32>,
    #[serde(rename = "encKeyValidation_DO_NOT_EDIT")]
    enc_key_validation: String,
    data: String,
}

/// Why an EncString did not open: unreadable, or readable but not under this key.
enum Open {
    Malformed,
    Mac,
}

/// `2.<iv>|<ciphertext>|<mac>`, each base64.
fn open(enc: &Key, mac: &Key, s: &str) -> Result<Zeroizing<Vec<u8>>, Open> {
    let rest = s.strip_prefix("2.").ok_or(Open::Malformed)?;
    let mut parts = rest.split('|').map(|p| STANDARD.decode(p));
    let (Some(Ok(iv)), Some(Ok(ct)), Some(Ok(tag)), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(Open::Malformed);
    };
    interop::aes256_cbc_hmac_decrypt(enc, mac, &iv, &ct, &tag).map_err(|_| Open::Mac)
}

fn master_key(e: &Envelope, password: &str) -> Result<Key, ImportError> {
    let pw = password.as_bytes();
    match e.kdf_type {
        0 => interop::pbkdf2_sha256(pw, e.salt.as_bytes(), e.kdf_iterations),
        // Bitwarden salts Argon2 with the SHA-256 of the salt string. `KdfParams` bounds the cost
        // (SR-23), so an export below its 19 MiB floor is refused as unsupported, not run.
        1 => {
            let m_kib = e.kdf_memory.and_then(|m| m.checked_mul(1024));
            KdfParams::new(
                m_kib.unwrap_or(0),
                e.kdf_iterations,
                e.kdf_parallelism.unwrap_or(0),
            )
            .and_then(|p| argon2id(pw, &sha256(e.salt.as_bytes()), p))
        }
        _ => Err(core_crypto::Error),
    }
    .map_err(|_| ImportError::Format)
}

/// Decrypt a password-protected Bitwarden JSON export with `password` and import it. A wrong
/// password is [`ImportError::WrongPassword`] and nothing is returned.
pub fn bitwarden_json_password(input: &[u8], password: &str) -> Result<Import, ImportError> {
    if input.len() > MAX_INPUT {
        return Err(ImportError::Format);
    }
    let e: Envelope = serde_json::from_slice(input).map_err(|_| ImportError::Format)?;
    if !(e.encrypted && e.password_protected) {
        return Err(ImportError::Format);
    }
    let master = master_key(&e, password)?;
    let enc = interop::hkdf_expand(&master, b"enc").map_err(|_| ImportError::Format)?;
    let mac = interop::hkdf_expand(&master, b"mac").map_err(|_| ImportError::Format)?;
    // The validation string is the password check: it opens only under the right key.
    match open(&enc, &mac, &e.enc_key_validation) {
        Ok(_) => {}
        Err(Open::Mac) => return Err(ImportError::WrongPassword),
        Err(Open::Malformed) => return Err(ImportError::Format),
    }
    let plain = open(&enc, &mac, &e.data).map_err(|_| ImportError::Format)?;
    bitwarden_json(&plain)
}
