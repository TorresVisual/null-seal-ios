//! WASM surface of the core for the Brave extension.
//!
//! Per decision #13 the extension holds no vault or keys, so this exposes only helpers that
//! need no stored secrets: the generator and the strength estimator, plus the cipher for one
//! desktop-bridge connection (#127). That session key is ephemeral: it is derived per connection,
//! never leaves WASM memory and is zeroized when the connection's object is freed.

use core_crypto::{Key, PUBLIC_LEN, decrypt, encrypt, x25519_public, x25519_shared};
use core_gen::{PasswordOpts, estimate, generate_password};
use wasm_bindgen::prelude::*;

/// Version of this build, for smoke tests and diagnostics.
#[wasm_bindgen]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// Random password of `length` characters with default rules (all classes).
#[wasm_bindgen]
pub fn generate(length: u32) -> Result<String, JsError> {
    let opts = PasswordOpts {
        length: length as usize,
        ..PasswordOpts::default()
    };
    // The Zeroizing wrapper is dropped here; the JS copy is out of our hands by design.
    Ok(generate_password(&opts)?.to_string())
}

/// zxcvbn score 0 (trivially guessable) to 4 (very unguessable).
#[wasm_bindgen]
pub fn strength(password: &str) -> u8 {
    estimate(password, &[]).score
}

fn js(_: core_crypto::Error) -> JsError {
    JsError::new("crypto failed")
}

/// This side's ephemeral X25519 key for one bridge connection.
#[wasm_bindgen]
pub struct BridgeEphemeral {
    secret: Key,
}

#[wasm_bindgen]
impl BridgeEphemeral {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<BridgeEphemeral, JsError> {
        Ok(Self {
            secret: Key::random().map_err(js)?,
        })
    }

    /// Known-answer tests only (feature `kat`): in the shipped build JS cannot choose the secret.
    #[cfg(feature = "kat")]
    pub fn from_secret(secret: &[u8]) -> Result<BridgeEphemeral, JsError> {
        let secret: [u8; 32] = secret.try_into().map_err(|_| JsError::new("bad key"))?;
        Ok(Self {
            secret: Key::from_bytes(secret),
        })
    }

    pub fn public(&self) -> Vec<u8> {
        x25519_public(&self.secret).to_vec()
    }

    /// Agree the session cipher with the peer's public key; `info` is the handshake transcript
    /// label. Fails on a low-order peer key.
    pub fn agree(&self, peer: &[u8], info: &[u8]) -> Result<BridgeCipher, JsError> {
        let peer: [u8; PUBLIC_LEN] = peer.try_into().map_err(|_| JsError::new("bad key"))?;
        Ok(BridgeCipher {
            key: x25519_shared(&self.secret, &peer, info).map_err(js)?,
        })
    }
}

/// XChaCha20-Poly1305 under the agreed session key.
#[wasm_bindgen]
pub struct BridgeCipher {
    key: Key,
}

#[wasm_bindgen]
impl BridgeCipher {
    /// `nonce || ciphertext || tag`, with a fresh random nonce.
    pub fn seal(&self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, JsError> {
        encrypt(&self.key, aad, plaintext).map_err(js)
    }

    pub fn open(&self, aad: &[u8], blob: &[u8]) -> Result<Vec<u8>, JsError> {
        // ponytail: wasm-bindgen copies a returned Vec into JS, outside our zeroizing; unavoidable
        // for a string handed to the caller.
        Ok(decrypt(&self.key, aad, blob).map_err(js)?.to_vec())
    }
}
