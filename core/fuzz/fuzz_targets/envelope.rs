//! Arbitrary bytes as an envelope: parsing and opening must never panic, and (without the
//! key) must never succeed.
#![no_main]
use core_crypto::Key;
use core_keys::{context, envelope_key_gen, open};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|blob: &[u8]| {
    let key = Key::from_bytes([7; 32]);
    let _ = envelope_key_gen(blob);
    assert!(open(&key, &context(&[b"x"]), blob).is_err());
});
