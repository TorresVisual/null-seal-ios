//! Google Authenticator's "Export accounts" link, `otpauth-migration://offline?data=<base64>`.
//! The data is a protobuf `MigrationPayload` holding one `OtpParameters` message per account.
//! Each time-based SHA-1/256/512 account becomes an ordinary `otpauth://totp/...` URI; anything
//! else (HOTP, MD5, a malformed entry) is counted in `skipped`, never silently dropped.

use crate::{Error, Otp, percent_decode};
use zeroize::Zeroizing;

const PREFIX: &str = "otpauth-migration://";
const BAD: Error = Error::InvalidUri("malformed migration data");

/// The accounts of one exported QR code. A large export spans several QR codes; each is one link.
pub struct Migration {
    /// One `otpauth://totp/...` URI per account. These hold secrets.
    pub uris: Vec<Zeroizing<String>>,
    /// Entries that cannot be turned into a time-based code here.
    pub skipped: usize,
}

/// Whether `text` is an `otpauth-migration://` link (without checking its data).
pub fn is_migration(text: &str) -> bool {
    text.trim()
        .get(..PREFIX.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(PREFIX))
}

/// Parse an `otpauth-migration://` link; an error if it is not one or its data is damaged.
pub fn parse_migration(link: &str) -> Result<Migration, Error> {
    if !is_migration(link) {
        return Err(Error::InvalidUri("not an otpauth-migration link"));
    }
    let rest = &link.trim()[PREFIX.len()..];
    let query = rest.split_once('?').map_or("", |(_, q)| q);
    let data = query
        .split('&')
        .find_map(|p| p.strip_prefix("data="))
        .ok_or(Error::InvalidUri("missing data"))?;
    let bytes = Zeroizing::new(base64_decode(&percent_decode(data)?).ok_or(BAD)?);

    let (mut uris, mut skipped) = (Vec::new(), 0);
    let mut payload = Reader(&bytes);
    while let Some((field, value)) = payload.next()? {
        if let (1, Value::Bytes(entry)) = (field, value) {
            match entry_uri(entry)? {
                Some(uri) => uris.push(uri),
                None => skipped += 1,
            }
        }
    }
    if uris.is_empty() && skipped == 0 {
        return Err(Error::InvalidUri("no accounts in migration data"));
    }
    Ok(Migration { uris, skipped })
}

/// `OtpParameters`: 1 secret, 2 name, 3 issuer, 4 algorithm, 5 digits, 6 type, 7 counter.
/// `Ok(None)` is an entry that is valid but not usable here; `Err` is damaged data.
fn entry_uri(entry: &[u8]) -> Result<Option<Zeroizing<String>>, Error> {
    let (mut secret, mut name, mut issuer): (&[u8], &[u8], &[u8]) = (&[], &[], &[]);
    let (mut algorithm, mut digits, mut kind) = (0, 0, 0);
    let mut r = Reader(entry);
    while let Some((field, value)) = r.next()? {
        match (field, value) {
            (1, Value::Bytes(b)) => secret = b,
            (2, Value::Bytes(b)) => name = b,
            (3, Value::Bytes(b)) => issuer = b,
            (4, Value::Varint(v)) => algorithm = v,
            (5, Value::Varint(v)) => digits = v,
            (6, Value::Varint(v)) => kind = v,
            _ => {}
        }
    }
    let alg = match algorithm {
        0 | 1 => "SHA1",
        2 => "SHA256",
        3 => "SHA512",
        _ => return Ok(None), // MD5
    };
    let digits = match digits {
        0 | 1 => 6,
        2 => 8,
        _ => return Ok(None),
    };
    let (Ok(name), Ok(issuer)) = (core::str::from_utf8(name), core::str::from_utf8(issuer)) else {
        return Ok(None);
    };
    if kind != 2 || secret.is_empty() {
        return Ok(None); // HOTP or unspecified
    }
    // The name is usually `Issuer:account`; the issuer field wins when both exist.
    let (issuer, account) = match (issuer, name.split_once(':')) {
        ("", Some((i, a))) => (i.trim(), a.trim()),
        (i, Some((_, a))) => (i, a.trim()),
        (i, None) => (i, name.trim()),
    };
    let mut uri = Zeroizing::new(format!(
        "otpauth://totp/{}?secret={}&algorithm={alg}&digits={digits}",
        percent_encode(account),
        *base32_encode(secret),
    ));
    if !issuer.is_empty() {
        uri.push_str("&issuer=");
        uri.push_str(&percent_encode(issuer));
    }
    // whatever we built must be something the rest of the app can read back
    Ok(Otp::from_uri(&uri).is_ok().then_some(uri))
}

enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Other,
}

/// Just enough protobuf wire format to walk a message.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn varint(&mut self) -> Result<u64, Error> {
        let mut v = 0u64;
        for shift in (0..70).step_by(7) {
            let (&b, rest) = self.0.split_first().ok_or(BAD)?;
            self.0 = rest;
            v |= u64::from(b & 0x7f).checked_shl(shift).ok_or(BAD)?;
            if b & 0x80 == 0 {
                return Ok(v);
            }
        }
        Err(BAD)
    }

    fn take(&mut self, n: u64) -> Result<&'a [u8], Error> {
        let n = usize::try_from(n).map_err(|_| BAD)?;
        let (head, rest) = self.0.split_at_checked(n).ok_or(BAD)?;
        self.0 = rest;
        Ok(head)
    }

    /// The next `(field number, value)`, or `None` at the end.
    fn next(&mut self) -> Result<Option<(u64, Value<'a>)>, Error> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let tag = self.varint()?;
        let value = match tag & 7 {
            0 => Value::Varint(self.varint()?),
            1 => {
                self.take(8)?;
                Value::Other
            }
            2 => {
                let n = self.varint()?;
                Value::Bytes(self.take(n)?)
            }
            5 => {
                self.take(4)?;
                Value::Other
            }
            _ => return Err(BAD),
        };
        Ok(Some((tag >> 3, value)))
    }
}

/// Standard or URL-safe base64, padding optional.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.trim_end_matches('=').bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

fn base32_encode(b: &[u8]) -> Zeroizing<String> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Zeroizing::new(String::new()));
    for &byte in b {
        acc = (acc << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(char::from(A[(acc >> bits) as usize & 31]));
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        out.push(char::from(A[(acc << (5 - bits)) as usize & 31]));
    }
    out
}

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                char::from(b).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}
