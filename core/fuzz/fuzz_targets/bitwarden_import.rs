//! Arbitrary bytes as a Bitwarden export file (untrusted input, SR-23): must not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = core_import::bitwarden_json(data);
});
