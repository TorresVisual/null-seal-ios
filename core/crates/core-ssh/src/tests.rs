#![allow(clippy::unwrap_used)]

use super::*;
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A scratch dir that is removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "core-ssh-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn has_ssh_keygen() -> bool {
    Command::new("ssh-keygen").arg("-?").output().is_ok()
}

/// `ssh-keygen -lf` on a public key line; `None` when the tool is not installed.
fn ssh_keygen_fingerprint(public: &str) -> Option<String> {
    let dir = Scratch::new("fp");
    let path = dir.0.join("k.pub");
    std::fs::write(&path, public).unwrap();
    let out = Command::new("ssh-keygen")
        .arg("-lf")
        .arg(&path)
        .output()
        .ok()?;
    let text = String::from_utf8(out.stdout).ok()?;
    text.split_whitespace().nth(1).map(str::to_owned)
}

/// Run `ssh-keygen -t <ty> -N <pass>` and return the private key file text.
fn ssh_keygen_make(dir: &Scratch, ty: &str, pass: &str) -> Option<(PathBuf, String)> {
    let path = dir.0.join(format!("{ty}-{}", pass.len()));
    let ok = Command::new("ssh-keygen")
        .args(["-q", "-t", ty, "-N", pass, "-C", "", "-f"])
        .arg(&path)
        .status()
        .ok()?
        .success();
    ok.then(|| (path.clone(), std::fs::read_to_string(&path).unwrap()))
}

fn round_trip(k: &SshKey) {
    let again = import(&k.private_openssh().unwrap()).unwrap();
    assert_eq!(again.public_openssh(), k.public_openssh());
    assert_eq!(again.fingerprint(), k.fingerprint());
    assert_eq!(
        again.private_openssh().unwrap(),
        k.private_openssh().unwrap()
    );
    if let Some(fp) = ssh_keygen_fingerprint(&k.public_openssh()) {
        assert_eq!(fp, k.fingerprint());
    }
}

#[test]
fn ed25519_round_trips_and_matches_ssh_keygen() {
    let k = generate_ed25519().unwrap();
    assert!(k.public_openssh().starts_with("ssh-ed25519 "));
    assert!(k.fingerprint().starts_with("SHA256:"));
    round_trip(&k);
}

#[test]
fn rsa_round_trips_and_matches_ssh_keygen() {
    let k = generate_rsa(2048).unwrap();
    assert!(k.public_openssh().starts_with("ssh-rsa "));
    round_trip(&k);
}

#[test]
fn rsa_size_is_bounded() {
    assert_eq!(generate_rsa(1024).unwrap_err(), Error::Unsupported);
    assert_eq!(generate_rsa(16384).unwrap_err(), Error::Unsupported);
}

#[test]
fn imports_keys_made_by_ssh_keygen() {
    if !has_ssh_keygen() {
        return;
    }
    let dir = Scratch::new("import");
    for ty in ["ed25519", "rsa"] {
        let (path, text) = ssh_keygen_make(&dir, ty, "").unwrap();
        let k = import(&text).unwrap();
        let theirs = std::fs::read_to_string(path.with_extension("pub")).unwrap();
        assert_eq!(k.public_openssh(), theirs.trim());
    }
}

#[test]
fn rejects_garbage_encrypted_and_other_algorithms() {
    assert_eq!(import("hello").unwrap_err(), Error::Format);
    assert_eq!(import("").unwrap_err(), Error::Format);
    if !has_ssh_keygen() {
        return;
    }
    let dir = Scratch::new("reject");
    let (_, enc) = ssh_keygen_make(&dir, "ed25519", "pw").unwrap();
    assert_eq!(import(&enc).unwrap_err(), Error::Encrypted);
    // ECDSA is not compiled in, so it fails to parse at all.
    let (_, ec) = ssh_keygen_make(&dir, "ecdsa", "").unwrap();
    assert_eq!(import(&ec).unwrap_err(), Error::Format);
}
