//! Password and passphrase generation, and strength estimation.
//!
//! Randomness comes only from the OS CSPRNG via `core-crypto`. Indices are drawn by
//! rejection sampling ([`uniform`]), so there is no modulo bias. The passphrase wordlist is
//! the EFF large wordlist (7776 words, CC BY 3.0, <https://www.eff.org/dice>).

use core_crypto::random_bytes;
use zeroize::Zeroizing;

const WORDS: &str = include_str!("eff_large.txt");
const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &[u8] = b"0123456789";
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.?";
const AMBIGUOUS: &[u8] = b"Il1O0";

pub const MAX_PASSWORD_LEN: usize = 128;
pub const MIN_WORDS: usize = 3;
pub const MAX_WORDS: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// The options cannot be satisfied (no class, length too short, word count out of range).
    InvalidOptions(&'static str),
    Rng,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidOptions(why) => write!(f, "invalid generator options: {why}"),
            Self::Rng => f.write_str("random number generator failed"),
        }
    }
}

impl core::error::Error for Error {}

/// Random character password options. An enabled class always contributes at least one
/// character; `min_digits` / `min_symbols` raise that floor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PasswordOpts {
    pub length: usize,
    pub lower: bool,
    pub upper: bool,
    pub digits: bool,
    pub symbols: bool,
    pub min_digits: usize,
    pub min_symbols: usize,
    /// Drop `I l 1 O 0` from every class.
    pub avoid_ambiguous: bool,
}

impl Default for PasswordOpts {
    fn default() -> Self {
        Self {
            length: 20,
            lower: true,
            upper: true,
            digits: true,
            symbols: true,
            min_digits: 1,
            min_symbols: 1,
            avoid_ambiguous: false,
        }
    }
}

/// Passphrase options.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PassphraseOpts {
    pub words: usize,
    pub separator: String,
    pub capitalize: bool,
    /// Append one random digit to one random word.
    pub include_number: bool,
}

impl Default for PassphraseOpts {
    fn default() -> Self {
        Self {
            words: 6,
            separator: "-".into(),
            capitalize: false,
            include_number: false,
        }
    }
}

type Rng<'a> = &'a mut dyn FnMut() -> Result<u32, Error>;

fn os_u32() -> Result<u32, Error> {
    random_bytes::<4>()
        .map(u32::from_le_bytes)
        .map_err(|_| Error::Rng)
}

/// Uniform integer in `0..n` (`1 <= n < 2^32`). Draws at or above the largest multiple of
/// `n` that fits in 2^32 are rejected, so every residue is equally likely.
fn uniform(n: usize, rng: Rng) -> Result<usize, Error> {
    let n = n as u64;
    let limit = (1u64 << 32) / n * n;
    loop {
        let x = u64::from(rng()?);
        if x < limit {
            return Ok((x % n) as usize);
        }
    }
}

fn pick<T: Copy>(set: &[T], rng: Rng) -> Result<T, Error> {
    Ok(set[uniform(set.len(), rng)?])
}

pub fn generate_password(opts: &PasswordOpts) -> Result<Zeroizing<String>, Error> {
    password_with(opts, &mut os_u32)
}

pub fn generate_passphrase(opts: &PassphraseOpts) -> Result<Zeroizing<String>, Error> {
    passphrase_with(opts, &mut os_u32)
}

fn password_with(opts: &PasswordOpts, rng: Rng) -> Result<Zeroizing<String>, Error> {
    // (charset, minimum count) per enabled class.
    let classes: Vec<(Vec<u8>, usize)> = [
        (opts.lower, LOWER, 1),
        (opts.upper, UPPER, 1),
        (opts.digits, DIGITS, opts.min_digits.max(1)),
        (opts.symbols, SYMBOLS, opts.min_symbols.max(1)),
    ]
    .into_iter()
    .filter(|(on, ..)| *on)
    .map(|(_, set, min)| {
        let set = set
            .iter()
            .copied()
            .filter(|c| !(opts.avoid_ambiguous && AMBIGUOUS.contains(c)))
            .collect();
        (set, min)
    })
    .collect();

    if classes.is_empty() {
        return Err(Error::InvalidOptions("no character class enabled"));
    }
    if !(1..=MAX_PASSWORD_LEN).contains(&opts.length) {
        return Err(Error::InvalidOptions("length out of range"));
    }
    if classes.iter().map(|(_, m)| m).sum::<usize>() > opts.length {
        return Err(Error::InvalidOptions("length below required minimums"));
    }

    let all: Vec<u8> = classes
        .iter()
        .flat_map(|(s, _)| s.iter().copied())
        .collect();
    let mut buf = Zeroizing::new(Vec::with_capacity(opts.length));
    for (set, min) in &classes {
        for _ in 0..*min {
            buf.push(pick(set, rng)?);
        }
    }
    while buf.len() < opts.length {
        buf.push(pick(&all, rng)?);
    }
    // Fisher-Yates, so the guaranteed characters are not clustered at the front.
    for i in (1..buf.len()).rev() {
        let j = uniform(i + 1, rng)?;
        buf.swap(i, j);
    }
    let mut out = Zeroizing::new(String::with_capacity(buf.len()));
    out.extend(buf.iter().map(|&b| char::from(b)));
    Ok(out)
}

fn passphrase_with(opts: &PassphraseOpts, rng: Rng) -> Result<Zeroizing<String>, Error> {
    if !(MIN_WORDS..=MAX_WORDS).contains(&opts.words) {
        return Err(Error::InvalidOptions("word count out of range"));
    }
    let list: Vec<&str> = WORDS.lines().collect();
    let number_at = if opts.include_number {
        Some(uniform(opts.words, rng)?)
    } else {
        None
    };
    let mut out = Zeroizing::new(String::new());
    for i in 0..opts.words {
        if i > 0 {
            out.push_str(&opts.separator);
        }
        let mut chars = pick(&list, rng)?.chars();
        match (opts.capitalize, chars.next()) {
            (true, Some(first)) => out.extend(first.to_uppercase()),
            (false, Some(first)) => out.push(first),
            (_, None) => {}
        }
        out.push_str(chars.as_str());
        if number_at == Some(i) {
            out.push(char::from(pick(DIGITS, rng)?));
        }
    }
    Ok(out)
}

/// zxcvbn result, reduced to what the UI needs.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Strength {
    /// 0 (trivially guessable) to 4 (very unguessable); below 3 counts as weak.
    pub score: u8,
    pub guesses_log10: f64,
}

/// Estimate strength. `user_inputs` (username, site, email…) are treated as known words.
pub fn estimate(password: &str, user_inputs: &[&str]) -> Strength {
    let e = zxcvbn::zxcvbn(password, user_inputs);
    Strength {
        score: u8::from(e.score()),
        guesses_log10: e.guesses_log10(),
    }
}

#[cfg(test)]
mod tests;
