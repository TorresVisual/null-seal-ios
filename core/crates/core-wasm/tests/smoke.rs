//! Runs the core through the compiled WASM module (`wasm-bindgen-test-runner`, Node).
#![cfg(all(target_family = "wasm", target_os = "unknown"))]
#![allow(clippy::unwrap_used)]

use core_wasm::{core_version, generate, strength};
use wasm_bindgen_test::wasm_bindgen_test;

#[wasm_bindgen_test]
fn core_runs_in_wasm() {
    assert!(!core_version().is_empty());
    // Exercises getrandom (wasm_js) through core-crypto and the zxcvbn clock binding.
    let pw = generate(24).unwrap();
    assert_eq!(pw.chars().count(), 24);
    assert_eq!(strength("password"), 0);
    assert_eq!(strength(&pw), 4);
}
