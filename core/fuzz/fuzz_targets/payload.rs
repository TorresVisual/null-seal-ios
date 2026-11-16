//! Arbitrary bytes as a decrypted payload (the parser a hostile-but-authentic record would
//! reach): must not panic, and anything that parses must re-serialize and re-parse equal.
#![no_main]
use core_vault::Payload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = serde_json::from_slice::<Payload>(data) {
        let again = serde_json::to_vec(&p).unwrap();
        assert_eq!(serde_json::from_slice::<Payload>(&again).unwrap(), p);
    }
});
