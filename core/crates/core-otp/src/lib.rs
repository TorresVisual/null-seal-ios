//! HOTP (RFC 4226), TOTP (RFC 6238) and `otpauth://` URI parsing.
//!
//! The HMAC itself comes from `core-crypto`; this crate only does dynamic truncation, time
//! stepping and the Key URI format. SHA-1 is supported because most services still issue it.

mod migration;

pub use migration::{Migration, is_migration, parse_migration};

use core_crypto::{HmacAlg, hmac};
use zeroize::Zeroizing;

pub const MIN_DIGITS: u32 = 6;
pub const MAX_DIGITS: u32 = 8;
pub const DEFAULT_PERIOD: u32 = 30;
const MAX_PERIOD: u32 = 86_400;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    /// digits or period outside the supported range, or an empty secret.
    InvalidParams(&'static str),
    /// Malformed `otpauth://` URI; the reason never contains URI content (it holds a secret).
    InvalidUri(&'static str),
    /// A link of another kind than `otpauth://`: the scheme name only, never the rest (it may be a secret).
    UnsupportedScheme(String),
    /// No readable QR code in the image, or the pixel buffer does not match its size.
    Qr(&'static str),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidParams(why) => write!(f, "invalid OTP parameters: {why}"),
            Self::InvalidUri(why) => write!(f, "invalid otpauth URI: {why}"),
            Self::UnsupportedScheme(s) => {
                write!(f, "unsupported link type `{s}`: expected otpauth://")
            }
            Self::Qr(why) => write!(f, "QR code: {why}"),
        }
    }
}

impl core::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

impl From<Algorithm> for HmacAlg {
    fn from(a: Algorithm) -> Self {
        match a {
            Algorithm::Sha1 => Self::Sha1,
            Algorithm::Sha256 => Self::Sha256,
            Algorithm::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Totp {
        period: u32,
    },
    /// Counter-based; the caller increments and persists `counter` after each use.
    Hotp {
        counter: u64,
    },
}

/// A parsed OTP entry: secret plus parameters. The secret is zeroized on drop and redacted
/// in `Debug`.
#[derive(Clone, PartialEq, Eq)]
pub struct Otp {
    pub kind: Kind,
    pub algorithm: Algorithm,
    pub digits: u32,
    pub issuer: Option<String>,
    /// Account name from the label (without the `issuer:` prefix).
    pub account: String,
    secret: Zeroizing<Vec<u8>>,
}

impl core::fmt::Debug for Otp {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Otp")
            .field("kind", &self.kind)
            .field("algorithm", &self.algorithm)
            .field("digits", &self.digits)
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("secret", &"<redacted>")
            .finish()
    }
}

/// HOTP value for `counter`, zero-padded to `digits` (6 to 8).
pub fn hotp(
    algorithm: Algorithm,
    secret: &[u8],
    counter: u64,
    digits: u32,
) -> Result<Zeroizing<String>, Error> {
    if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
        return Err(Error::InvalidParams("digits must be 6 to 8"));
    }
    if secret.is_empty() {
        return Err(Error::InvalidParams("empty secret"));
    }
    let h = Zeroizing::new(
        hmac(algorithm.into(), secret, &counter.to_be_bytes())
            .map_err(|_| Error::InvalidParams("hmac failed"))?,
    );
    let off = usize::from(h[h.len() - 1] & 0x0f);
    let bin = u32::from_be_bytes([h[off] & 0x7f, h[off + 1], h[off + 2], h[off + 3]]);
    let code = bin % 10u32.pow(digits);
    Ok(Zeroizing::new(format!(
        "{code:0width$}",
        width = digits as usize
    )))
}

/// TOTP value at `unix_time` (seconds) with the given `period`.
pub fn totp(
    algorithm: Algorithm,
    secret: &[u8],
    unix_time: u64,
    period: u32,
    digits: u32,
) -> Result<Zeroizing<String>, Error> {
    if !(1..=MAX_PERIOD).contains(&period) {
        return Err(Error::InvalidParams("period out of range"));
    }
    hotp(algorithm, secret, unix_time / u64::from(period), digits)
}

impl Otp {
    /// Current code: for TOTP the one valid at `unix_time`, for HOTP the one for the stored
    /// counter (`unix_time` is ignored).
    pub fn code(&self, unix_time: u64) -> Result<Zeroizing<String>, Error> {
        match self.kind {
            Kind::Totp { period } => {
                totp(self.algorithm, &self.secret, unix_time, period, self.digits)
            }
            Kind::Hotp { counter } => hotp(self.algorithm, &self.secret, counter, self.digits),
        }
    }

    /// Seconds until the code at `unix_time` stops being valid (`period` for a TOTP just stepped), or
    /// `None` for HOTP, whose codes do not expire.
    pub fn remaining(&self, unix_time: u64) -> Option<u32> {
        match self.kind {
            Kind::Totp { period } => Some(period - (unix_time % u64::from(period)) as u32),
            Kind::Hotp { .. } => None,
        }
    }

    /// A name for the entry: `Issuer (account)`, whichever parts exist.
    pub fn label(&self) -> String {
        match (self.issuer.as_deref(), self.account.as_str()) {
            (Some(i), "") => i.to_owned(),
            (Some(i), a) => format!("{i} ({a})"),
            (None, a) => a.to_owned(),
        }
    }

    /// A TOTP as vault items store it: an `otpauth://` URI or a bare base32 secret (30 s, 6 digits, SHA-1).
    /// `steam://` and anything else is an error.
    pub fn parse(stored: &str) -> Result<Self, Error> {
        let s = stored.trim();
        if s.get(..10)
            .is_some_and(|p| p.eq_ignore_ascii_case("otpauth://"))
        {
            Self::from_uri(s)
        } else if let Some((scheme, _)) = s.split_once("://") {
            // only a plain scheme name is echoed; anything else could be part of a secret
            let plain = scheme.len() <= 32
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+-.".contains(c));
            Err(Error::UnsupportedScheme(if plain {
                scheme.to_ascii_lowercase()
            } else {
                "?".into()
            }))
        } else {
            let secret = Zeroizing::new(base32_decode(s)?);
            if secret.is_empty() {
                return Err(Error::InvalidUri("empty secret"));
            }
            Ok(Self {
                kind: Kind::Totp {
                    period: DEFAULT_PERIOD,
                },
                algorithm: Algorithm::Sha1,
                digits: 6,
                issuer: None,
                account: String::new(),
                secret,
            })
        }
    }

    /// Parse an `otpauth://totp/...` or `otpauth://hotp/...` Key URI
    /// (<https://github.com/google/google-authenticator/wiki/Key-Uri-Format>).
    ///
    /// Lenient where real-world providers differ: base32 secret is case-insensitive with
    /// optional padding/spaces, unknown parameters are ignored, the `issuer` parameter wins
    /// over the label prefix.
    pub fn from_uri(uri: &str) -> Result<Self, Error> {
        const BAD: Error = Error::InvalidUri("malformed");
        let (scheme, rest) = uri.trim().split_once("://").ok_or(BAD)?;
        if !scheme.eq_ignore_ascii_case("otpauth") {
            return Err(Error::InvalidUri("scheme is not otpauth"));
        }
        let rest = rest.split('#').next().unwrap_or_default();
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let (typ, label) = path.split_once('/').ok_or(BAD)?;

        let label = percent_decode(label)?;
        let (label_issuer, account) = match label.split_once(':') {
            Some((i, a)) => (Some(i.trim().to_owned()), a.trim().to_owned()),
            None => (None, label.trim().to_owned()),
        };

        let (mut secret, mut issuer, mut algorithm, mut digits, mut period, mut counter) =
            (None, None, None, None, None, None);
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            // First occurrence wins; unknown keys are ignored.
            let slot = match k.to_ascii_lowercase().as_str() {
                "secret" => &mut secret,
                "issuer" => &mut issuer,
                "algorithm" => &mut algorithm,
                "digits" => &mut digits,
                "period" => &mut period,
                "counter" => &mut counter,
                _ => continue,
            };
            slot.get_or_insert(percent_decode(v)?);
        }

        let secret = Zeroizing::new(base32_decode(
            &secret.ok_or(Error::InvalidUri("missing secret"))?,
        )?);
        if secret.is_empty() {
            return Err(Error::InvalidUri("empty secret"));
        }
        let algorithm = match algorithm.map(|a| a.to_ascii_uppercase()).as_deref() {
            None | Some("SHA1") => Algorithm::Sha1,
            Some("SHA256") => Algorithm::Sha256,
            Some("SHA512") => Algorithm::Sha512,
            Some(_) => return Err(Error::InvalidUri("unsupported algorithm")),
        };
        let digits = match digits {
            None => 6,
            Some(d) => d.parse().map_err(|_| Error::InvalidUri("bad digits"))?,
        };
        if !(MIN_DIGITS..=MAX_DIGITS).contains(&digits) {
            return Err(Error::InvalidUri("digits must be 6 to 8"));
        }
        let kind = match typ.to_ascii_lowercase().as_str() {
            "totp" => {
                let period = match period {
                    None => DEFAULT_PERIOD,
                    Some(p) => p.parse().map_err(|_| Error::InvalidUri("bad period"))?,
                };
                if !(1..=MAX_PERIOD).contains(&period) {
                    return Err(Error::InvalidUri("period out of range"));
                }
                Kind::Totp { period }
            }
            "hotp" => Kind::Hotp {
                counter: counter
                    .ok_or(Error::InvalidUri("hotp requires counter"))?
                    .parse()
                    .map_err(|_| Error::InvalidUri("bad counter"))?,
            },
            _ => return Err(Error::InvalidUri("type must be totp or hotp")),
        };

        Ok(Self {
            kind,
            algorithm,
            digits,
            issuer: issuer.or(label_issuer).filter(|i| !i.is_empty()),
            account,
            secret,
        })
    }
}

/// The text of the first QR code in an 8-bit grayscale image (`luma`, row-major, `width * height`
/// bytes). Decoding images (PNG, JPEG, ...) into pixels is the client's job, which keeps image
/// codecs out of core. The text is an `otpauth://` URI, i.e. a secret, hence `Zeroizing`.
pub fn decode_qr(width: usize, height: usize, luma: &[u8]) -> Result<Zeroizing<String>, Error> {
    if width.checked_mul(height) != Some(luma.len()) {
        return Err(Error::Qr("pixel buffer does not match the image size"));
    }
    let mut img =
        rqrr::PreparedImage::prepare_from_greyscale(width, height, |x, y| luma[y * width + x]);
    img.detect_grids()
        .into_iter()
        .find_map(|g| g.decode().ok())
        .map(|(_, text)| Zeroizing::new(text))
        .ok_or(Error::Qr("no readable code found"))
}

/// Decode `%XX` escapes (UTF-8). `+` stays literal: otpauth producers use `%20`.
pub(crate) fn percent_decode(s: &str) -> Result<String, Error> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let hex = b.get(i + 1..i + 3).ok_or(Error::InvalidUri("bad escape"))?;
            let hex = core::str::from_utf8(hex).map_err(|_| Error::InvalidUri("bad escape"))?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| Error::InvalidUri("bad escape"))?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| Error::InvalidUri("not utf-8"))
}

/// RFC 4648 base32, case-insensitive, whitespace and trailing `=` ignored.
fn base32_decode(s: &str) -> Result<Vec<u8>, Error> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s
        .trim_end_matches('=')
        .chars()
        .filter(|c| !c.is_whitespace())
    {
        let v = match c.to_ascii_uppercase() {
            c @ 'A'..='Z' => c as u32 - 'A' as u32,
            c @ '2'..='7' => c as u32 - '2' as u32 + 26,
            _ => return Err(Error::InvalidUri("secret is not base32")),
        };
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests;
