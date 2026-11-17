//! SSH keys for the vault (#63): generate or import an Ed25519 or RSA key, keep the private
//! key as an unencrypted OpenSSH file (the vault seals it), and derive the public key line
//! and the `SHA256:` fingerprint `ssh-keygen -lf` prints. Parsing and encoding come from
//! RustCrypto's `ssh-key`; nothing here touches key material itself.

use ssh_key::{
    Algorithm, HashAlg, LineEnding, PrivateKey,
    private::{KeypairData, RsaKeypair},
    rand_core::UnwrapErr,
};
use zeroize::Zeroizing;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// Not an OpenSSH private key, malformed, or of an algorithm this build cannot parse.
    Format,
    /// Passphrase-protected; the vault already encrypts it, so import it unprotected.
    Encrypted,
    /// Only Ed25519 and RSA (2048 to 8192 bits) are stored.
    Unsupported,
    /// The OS random source or key generation failed.
    Generate,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Format => "not a valid OpenSSH Ed25519 or RSA private key",
            Self::Encrypted => {
                "passphrase-protected keys are not supported; remove the passphrase first"
            }
            Self::Unsupported => "only Ed25519 and RSA keys are supported",
            Self::Generate => "key generation failed",
        })
    }
}

impl core::error::Error for Error {}

/// A parsed private key. `Debug` shows only the fingerprint.
pub struct SshKey(PrivateKey);

impl core::fmt::Debug for SshKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("SshKey").field(&self.fingerprint()).finish()
    }
}

fn rng() -> UnwrapErr<getrandom::SysRng> {
    UnwrapErr(getrandom::SysRng)
}

pub fn generate_ed25519() -> Result<SshKey, Error> {
    PrivateKey::random(&mut rng(), Algorithm::Ed25519)
        .map(SshKey)
        .map_err(|_| Error::Generate)
}

pub fn generate_rsa(bits: usize) -> Result<SshKey, Error> {
    if !(2048..=8192).contains(&bits) {
        return Err(Error::Unsupported);
    }
    let pair = RsaKeypair::random(&mut rng(), bits).map_err(|_| Error::Generate)?;
    PrivateKey::try_from(KeypairData::from(pair))
        .map(SshKey)
        .map_err(|_| Error::Generate)
}

/// Parse an OpenSSH private key (`-----BEGIN OPENSSH PRIVATE KEY-----`).
pub fn import(text: &str) -> Result<SshKey, Error> {
    let key = PrivateKey::from_openssh(text.trim()).map_err(|_| Error::Format)?;
    if key.is_encrypted() {
        return Err(Error::Encrypted);
    }
    match key.algorithm() {
        Algorithm::Ed25519 | Algorithm::Rsa { .. } => Ok(SshKey(key)),
        _ => Err(Error::Unsupported),
    }
}

impl SshKey {
    /// The OpenSSH private key file, as stored in the vault.
    pub fn private_openssh(&self) -> Result<Zeroizing<String>, Error> {
        self.0.to_openssh(LineEnding::LF).map_err(|_| Error::Format)
    }

    /// One `authorized_keys` line (`ssh-ed25519 AAAA...`), without a comment.
    pub fn public_openssh(&self) -> String {
        let mut p = self.0.public_key().clone();
        p.set_comment("");
        p.to_openssh().unwrap_or_default()
    }

    /// `SHA256:<base64>`, as `ssh-keygen -lf` prints it.
    pub fn fingerprint(&self) -> String {
        self.0.fingerprint(HashAlg::Sha256).to_string()
    }
}

#[cfg(test)]
mod tests;
