//! Scan for #73: the import fixtures must hold no real credentials. A real secret nearly always
//! travels with a real host or email, so every one must sit on a reserved domain (RFC 2606);
//! on top of that, no file may carry the signature of a well-known token or private key.
#![allow(clippy::unwrap_used)]

use std::path::Path;

const RESERVED: [&str; 6] = [
    "example.com",
    "example.net",
    "example.org",
    "test",
    "invalid",
    "localhost",
];

// Prefixes of real-world secrets (AWS, GitHub, Slack, Stripe, Google, GitLab, PEM keys).
const TOKEN_SIGNATURES: [&str; 7] = [
    "-----BEGIN",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "sk_live_",
    "AIza",
    "glpat-",
];

fn reserved(host: &str) -> bool {
    RESERVED
        .iter()
        .any(|r| host == *r || host.ends_with(&format!(".{r}")))
}

/// AWS key ids are `AKIA`/`ASIA` + 16 upper-case alphanumerics; the bare prefix shows up by chance in base64 ciphertext.
fn has_aws_key_id(text: &str) -> bool {
    ["AKIA", "ASIA"].iter().any(|p| {
        text.match_indices(p).any(|(i, _)| {
            let id = &text[i + 4..];
            id.len() >= 16
                && id[..16]
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
    })
}

fn host_chars(s: &str) -> &str {
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-'))
        .unwrap_or(s.len());
    s[..end].trim_end_matches('.')
}

/// Every host of an http(s) URL and every email domain in `text`.
fn hosts(text: &str) -> Vec<&str> {
    let urls = ["https://", "http://"].iter().flat_map(|p| {
        text.match_indices(p)
            .map(move |(i, _)| &text[i + p.len()..])
    });
    let emails = text.match_indices('@').map(|(i, _)| &text[i + 1..]);
    urls.chain(emails)
        .map(host_chars)
        // `https://.*` is a regex match rule, not a host.
        .filter(|h| h.chars().any(|c| c.is_ascii_alphabetic()))
        .collect()
}

fn fixtures(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            fixtures(&p, out);
        } else {
            out.push(p);
        }
    }
}

#[test]
fn fixtures_hold_only_synthetic_data() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut files = Vec::new();
    fixtures(&root, &mut files);
    assert!(files.len() >= 5, "fixture directory not found: {root:?}");
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        for h in hosts(&text) {
            assert!(reserved(h), "{f:?}: host {h} is not a reserved domain");
        }
        assert!(!has_aws_key_id(&text), "{f:?}: looks like an AWS key id");
        for sig in TOKEN_SIGNATURES {
            assert!(
                !text.contains(sig),
                "{f:?}: looks like a real token ({sig})"
            );
        }
    }
}

#[test]
fn the_scan_catches_what_it_should() {
    assert_eq!(
        hosts("see https://bank.com/x, a@b.org and https://.*"),
        ["bank.com", "b.org"]
    );
    assert!(has_aws_key_id("k=AKIAIOSFODNN7EXAMPLE") && !has_aws_key_id("2.AKIAbc+/def"));
    assert!(reserved("mail.example.com") && !reserved("notexample.com"));
}
