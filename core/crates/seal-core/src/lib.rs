//! Null Seal core entry crate: the session that gates keys and items behind unlock.

pub mod account;
pub mod session;

/// Crate version, for diagnostics and binding smoke tests.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    #[test]
    fn version_is_set() {
        assert!(!super::version().is_empty());
    }
}
