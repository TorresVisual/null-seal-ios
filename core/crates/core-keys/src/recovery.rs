//! Recovery key (ADR 0001 §7, SR-7): 256 random bits shown once at setup, encoded for humans
//! as Crockford base32 in groups of 5 with a 2-character checksum, so typos are detected
//! rather than guessed. The only thing that exists server-side is the recovery *wrapper*
//! of the Account Key; there is no escrow and no other path to the vault.
//!
//! Code layout: 52 symbols for the 256 key bits (the last carries 1 data bit, 4 zero pad
//! bits, which decoding insists on) + 2 checksum symbols = 54, shown as `XXXXX-XXXXX-...`.

use crate::{MasterHeader, Wrapper, unwrap_account_key, wrap_account_key};
use core_crypto::{Error, KdfParams, Key};
use zeroize::Zeroizing;

/// Crockford base32: no I, L, O, U.
const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const KEY_SYMBOLS: usize = 52;
const CODE_SYMBOLS: usize = KEY_SYMBOLS + 2;

#[derive(Debug, PartialEq, Eq)]
pub enum RecoveryError {
    /// Wrong length, a character outside the alphabet, or non-zero padding.
    Malformed,
    /// Well-formed but a symbol was mistyped: the checksum does not match.
    Checksum,
    /// Valid code, but it does not open the wrapper (wrong vault, or tampered blob).
    Crypto,
}

impl From<Error> for RecoveryError {
    fn from(_: Error) -> Self {
        Self::Crypto
    }
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "recovery key is malformed",
            Self::Checksum => "recovery key checksum mismatch",
            Self::Crypto => "recovery key did not open the vault",
        })
    }
}

impl core::error::Error for RecoveryError {}

/// Fresh 256-bit recovery key from the OS CSPRNG. No KDF: it already has full entropy.
pub fn new_recovery_key() -> Result<Key, Error> {
    Key::random()
}

/// 10-bit checksum (two symbols): position-weighted sum of the key symbols mod the prime 1021.
/// Unlike a hash this *guarantees* detection of any single mistyped symbol and any swap of
/// two adjacent different symbols (1021 is prime and larger than every weight and symbol
/// difference). It is not a MAC: it only catches typos and reveals at most 10 bits of the key.
fn checksum(key_symbols: &[u8]) -> [u8; 2] {
    let sum: u32 = (1..).zip(key_symbols).map(|(w, &s)| w * u32::from(s)).sum();
    let v = sum % 1021;
    [(v >> 5) as u8 & 31, v as u8 & 31]
}

/// Human-friendly code for the key, e.g. `0123A-...-XYZ1`. Show once, never store.
pub fn encode_recovery_key(key: &Key) -> Zeroizing<String> {
    let mut syms = Zeroizing::new(Vec::with_capacity(CODE_SYMBOLS));
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in key.expose() {
        acc = (acc << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            syms.push((acc >> bits) as u8 & 31);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        syms.push((acc << (5 - bits)) as u8 & 31);
    }
    let sum = checksum(&syms);
    syms.extend(sum);

    let mut out = Zeroizing::new(String::with_capacity(CODE_SYMBOLS + CODE_SYMBOLS / 5));
    for (i, &s) in syms.iter().enumerate() {
        if i > 0 && i % 5 == 0 {
            out.push('-');
        }
        out.push(ALPHABET[usize::from(s)] as char);
    }
    out
}

/// Parse a typed code. Case-insensitive; `-` and spaces ignored; Crockford's `O`→0 and
/// `I`/`L`→1 are accepted.
pub fn decode_recovery_key(code: &str) -> Result<Key, RecoveryError> {
    let mut syms = Zeroizing::new(Vec::with_capacity(CODE_SYMBOLS));
    for c in code.chars().filter(|c| !matches!(c, '-' | ' ')) {
        syms.push(symbol(c).ok_or(RecoveryError::Malformed)?);
    }
    if syms.len() != CODE_SYMBOLS {
        return Err(RecoveryError::Malformed);
    }

    let mut key = Zeroizing::new([0u8; 32]);
    let (mut acc, mut bits, mut n) = (0u32, 0u32, 0usize);
    for &s in &syms[..KEY_SYMBOLS] {
        acc = (acc << 5) | u32::from(s);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key[n] = (acc >> bits) as u8;
            n += 1;
            acc &= (1 << bits) - 1;
        }
    }
    if acc != 0 {
        return Err(RecoveryError::Malformed); // non-canonical padding
    }
    if syms[KEY_SYMBOLS..] != checksum(&syms[..KEY_SYMBOLS]) {
        return Err(RecoveryError::Checksum);
    }
    Ok(Key::from_bytes(*key))
}

fn symbol(c: char) -> Option<u8> {
    let c = match c.to_ascii_uppercase() {
        'O' => '0',
        'I' | 'L' => '1',
        c => c,
    };
    ALPHABET
        .iter()
        .position(|&a| a as char == c)
        .map(|i| i as u8)
}

/// Verify-by-retyping at setup: does what the user typed decode to exactly this key?
pub fn verify_retyped(key: &Key, typed: &str) -> bool {
    decode_recovery_key(typed).is_ok_and(|k| k == *key)
}

/// Everything a restore produces. The caller stores the two wrappers (and the header) in
/// place of the old ones, shows `recovery_code` once, then drops this struct.
pub struct Restored {
    pub account_key: Key,
    pub master_header: MasterHeader,
    pub master_wrapper: Vec<u8>,
    pub recovery_code: Zeroizing<String>,
    pub recovery_wrapper: Vec<u8>,
}

/// Restore on a fresh device from the stored recovery wrapper and the typed code alone:
/// open the Account Key, wrap it under the new master password (fresh salt), and rotate
/// the recovery key (the old code stops working once the old wrapper is replaced).
/// Nothing is returned unless every step succeeds. Password strength is the caller's gate (#18).
pub fn restore(
    recovery_wrapper: &[u8],
    code: &str,
    new_password: &str,
    params: KdfParams,
) -> Result<Restored, RecoveryError> {
    let old = decode_recovery_key(code)?;
    let ak = unwrap_account_key(recovery_wrapper, &Wrapper::Recovery(&old))?;

    let master_header = MasterHeader::new(params)?;
    let master_wrapper = wrap_account_key(
        &ak,
        &Wrapper::Master {
            password: new_password,
            header: &master_header,
        },
    )?;
    let new_key = new_recovery_key()?;
    Ok(Restored {
        recovery_code: encode_recovery_key(&new_key),
        recovery_wrapper: wrap_account_key(&ak, &Wrapper::Recovery(&new_key))?,
        account_key: ak,
        master_header,
        master_wrapper,
    })
}

#[cfg(test)]
mod tests;
