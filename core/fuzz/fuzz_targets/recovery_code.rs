//! Arbitrary text as a typed recovery code: must not panic; a code that decodes must
//! re-encode to something that decodes to the same key.
#![no_main]
use core_keys::{decode_recovery_key, encode_recovery_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|code: &str| {
    if let Ok(k) = decode_recovery_key(code) {
        assert!(decode_recovery_key(&encode_recovery_key(&k)).unwrap() == k);
    }
});
