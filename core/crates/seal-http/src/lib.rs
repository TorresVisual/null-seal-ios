//! HTTPS transport for `core-sync`, built on ureq with rustls and the OS certificate store.
//! The relay base URL is runtime configuration and never appears in this repository.

use core_sync::{Request, Response, Transport, TransportError};
use std::time::Duration;

pub struct Http {
    base: String,
    agent: ureq::Agent,
}

impl Http {
    /// `base` is the relay origin, e.g. `https://relay.example`.
    /// Plain `http://` is accepted only for loopback (local development and the harness).
    pub fn new(base: &str) -> Result<Self, TransportError> {
        let base = base.trim().trim_end_matches('/').to_owned();
        let local = is_loopback_http(&base);
        if !base.starts_with("https://") && !local {
            return Err(TransportError("relay URL must be https".into()));
        }
        let agent = agent();
        Ok(Self { base, agent })
    }
}

impl Transport for Http {
    fn send(&self, req: &Request) -> Result<Response, TransportError> {
        let url = format!("{}{}", self.base, req.path);
        let err = |e: ureq::Error| TransportError(e.to_string());
        // The method is part of the signed message, so it must go out exactly as signed.
        let mut res = match req.method {
            "GET" | "DELETE" => {
                let mut b = if req.method == "GET" {
                    self.agent.get(&url)
                } else {
                    self.agent.delete(&url)
                };
                for (k, v) in &req.headers {
                    b = b.header(*k, v);
                }
                b.call().map_err(err)?
            }
            "POST" | "PUT" => {
                let mut b = if req.method == "PUT" {
                    self.agent.put(&url)
                } else {
                    self.agent.post(&url)
                };
                for (k, v) in &req.headers {
                    b = b.header(*k, v);
                }
                b.header("content-type", "application/json")
                    .send(&req.body[..])
                    .map_err(err)?
            }
            m => return Err(TransportError(format!("unsupported method {m}"))),
        };
        let status = res.status().as_u16();
        let body = res.body_mut().read_to_vec().map_err(err)?;
        Ok(Response { status, body })
    }
}

/// The OS certificate store decides who is trusted, not a bundled root list.
fn agent() -> ureq::Agent {
    let roots: Vec<_> = rustls_native_certs::load_native_certs()
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    ureq::Agent::config_builder()
        .timeout_global(Some(Duration::from_secs(30)))
        .http_status_as_error(false)
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .provider(ureq::tls::TlsProvider::Rustls)
                .root_certs(ureq::tls::RootCerts::Specific(std::sync::Arc::new(roots)))
                .build(),
        )
        .build()
        .into()
}

pub const PWNED_BASE: &str = "https://api.pwnedpasswords.com";

/// Pwned Passwords range query (#71): `GET {base}/range/{prefix}` with `Add-Padding`, so the
/// response size does not reveal how many hashes share the prefix. Only the 5-hex-character
/// prefix goes on the wire. `base` is a parameter so tests can point it at a loopback listener.
pub fn pwned_range(base: &str, prefix: &str) -> Result<String, TransportError> {
    if prefix.len() != 5 || !prefix.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(TransportError("a range prefix is 5 hex characters".into()));
    }
    let base = base.trim_end_matches('/');
    if !base.starts_with("https://") && !is_loopback_http(base) {
        return Err(TransportError("breach service URL must be https".into()));
    }
    let err = |e: ureq::Error| TransportError(e.to_string());
    let mut res = agent()
        .get(&format!("{base}/range/{prefix}"))
        .header("Add-Padding", "true")
        .call()
        .map_err(err)?;
    if res.status().as_u16() != 200 {
        return Err(TransportError(format!(
            "breach service answered {}",
            res.status().as_u16()
        )));
    }
    res.body_mut().read_to_string().map_err(err)
}

/// `http://` is allowed only for an exact loopback host (optional numeric port, no userinfo),
/// so a typo such as `http://localhost.evil.com` cannot send tokens in cleartext.
fn is_loopback_http(base: &str) -> bool {
    let Some(rest) = base.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or_default();
    let (host, port) = if let Some(end) = authority.strip_prefix('[').and_then(|a| a.find(']')) {
        (
            &authority[..=end + 1],
            authority[end + 2..].strip_prefix(':'),
        )
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        }
    };
    let rest_ok = authority.len() == host.len() || port.is_some();
    rest_ok
        && port.is_none_or(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        && matches!(host, "localhost" | "127.0.0.1" | "[::1]")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn plain_http_only_for_exact_loopback() {
        for ok in [
            "http://localhost",
            "http://localhost:8787",
            "http://127.0.0.1:1/x",
            "http://[::1]:8787",
            "http://[::1]",
        ] {
            assert!(is_loopback_http(ok), "{ok}");
        }
        for bad in [
            "http://localhost.evil.com",
            "http://localhost@evil.com",
            "http://127.0.0.1.evil.com",
            "http://evil.com/localhost",
            "http://localhost:80@evil.com",
            "http://localhost:",
            "http://[::1]x",
            "https://localhost",
        ] {
            assert!(!is_loopback_http(bad), "{bad}");
        }
    }

    #[test]
    fn range_query_sends_only_the_prefix_with_padding() {
        use std::io::{Read, Write};
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", l.local_addr().unwrap());
        let server = std::thread::spawn(move || {
            let (mut c, _) = l.accept().unwrap();
            let mut buf = [0u8; 4096];
            let n = c.read(&mut buf).unwrap();
            let body = "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n";
            let head = format!(
                "HTTP/1.1 200 OK\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            c.write_all(head.as_bytes()).unwrap();
            c.write_all(body.as_bytes()).unwrap();
            String::from_utf8_lossy(&buf[..n]).into_owned()
        });
        let got = pwned_range(&base, "21BD1").unwrap();
        assert!(got.starts_with("0018A45C"));
        let req = server.join().unwrap().to_lowercase();
        // the request line carries the 5-character prefix and nothing else of the hash
        assert_eq!(
            req.lines().next(),
            Some("get /range/21bd1 http/1.1"),
            "{req}"
        );
        assert!(req.contains("add-padding: true"), "{req}");

        for bad in ["21BD", "21BD12", "21BDZ", "21BD1/../x"] {
            assert!(pwned_range(&base, bad).is_err(), "{bad}");
        }
        assert!(pwned_range("http://evil.example", "21BD1").is_err());
    }
}
