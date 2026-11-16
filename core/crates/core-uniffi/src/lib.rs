//! UniFFI surface of the core for the iOS app (Swift bindings are generated, not committed).
//!
//! Grows with the core; today it exposes enough to prove the toolchain end to end.

uniffi::setup_scaffolding!();

/// Generator failure as seen from Swift (no detail: it can never contain a secret).
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum GenError {
    #[error("password generation failed")]
    Failed,
}

/// Version of the Rust core this binding was built from.
#[uniffi::export]
pub fn core_version() -> String {
    seal_core::version().to_owned()
}

/// Random password of `length` characters with default rules (all classes).
#[uniffi::export]
pub fn generate_password(length: u32) -> Result<String, GenError> {
    let opts = core_gen::PasswordOpts {
        length: length as usize,
        ..Default::default()
    };
    core_gen::generate_password(&opts)
        .map(|p| p.to_string())
        .map_err(|_| GenError::Failed)
}

/// zxcvbn score 0 (trivially guessable) to 4 (very unguessable).
#[uniffi::export]
pub fn estimate_strength(password: String) -> u8 {
    core_gen::estimate(&password, &[]).score
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn exported_functions_work() {
        assert_eq!(core_version(), seal_core::version());
        assert_eq!(generate_password(30).unwrap().chars().count(), 30);
        assert!(generate_password(0).is_err());
        assert_eq!(estimate_strength("password".into()), 0);
    }
}
