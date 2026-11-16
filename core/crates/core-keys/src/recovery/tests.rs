#![allow(clippy::unwrap_used)]

use super::*;
use crate::{new_vault_key, open, seal, unwrap_vault_key, wrap_vault_key};

fn fast() -> KdfParams {
    KdfParams::new(19 * 1024, 2, 1).unwrap()
}

fn code_of(b: u8) -> String {
    encode_recovery_key(&Key::from_bytes([b; 32])).to_string()
}

#[test]
fn known_answer_encoding() {
    // 256 zero bits -> 52 zero symbols; 256 one bits -> 51 'Z' + last symbol 0b1_0000 = 'G'.
    let zeros = code_of(0x00);
    assert!(zeros.starts_with("00000-00000-"), "{zeros}");
    assert_eq!(zeros.replace('-', "")[..52], "0".repeat(52));
    let ones = code_of(0xff).replace('-', "");
    assert_eq!(ones[..52], format!("{}G", "Z".repeat(51)));
    // 54 symbols in groups of 5 (last group of 4)
    assert_eq!(zeros.split('-').map(str::len).collect::<Vec<_>>(), {
        let mut v = vec![5; 10];
        v.push(4);
        v
    });
}

#[test]
fn round_trips_and_is_forgiving_about_formatting() {
    for _ in 0..50 {
        let k = new_recovery_key().unwrap();
        let code = encode_recovery_key(&k);
        assert_eq!(decode_recovery_key(&code).unwrap(), k);
        // lowercase, spaces instead of dashes, no separators
        let loose = code.to_lowercase().replace('-', " ");
        assert_eq!(decode_recovery_key(&loose).unwrap(), k);
        assert_eq!(decode_recovery_key(&code.replace('-', "")).unwrap(), k);
    }
    // Crockford aliases: O=0, I=L=1
    let k = Key::from_bytes([0; 32]);
    let aliased = code_of(0).replace('0', "o");
    assert_eq!(decode_recovery_key(&aliased).unwrap(), k);
}

#[test]
fn every_single_symbol_typo_is_detected() {
    let k = new_recovery_key().unwrap();
    let code = encode_recovery_key(&k).replace('-', "");
    for i in 0..code.len() {
        for &a in ALPHABET {
            if a as char == code.as_bytes()[i] as char {
                continue;
            }
            let mut t = code.clone().into_bytes();
            t[i] = a;
            let r = decode_recovery_key(std::str::from_utf8(&t).unwrap());
            assert!(r.is_err(), "typo at {i} -> {} accepted", a as char);
        }
    }
}

#[test]
fn adjacent_swaps_are_detected() {
    let k = new_recovery_key().unwrap();
    let code = encode_recovery_key(&k).replace('-', "").into_bytes();
    for i in 0..code.len() - 1 {
        if code[i] == code[i + 1] {
            continue;
        }
        let mut t = code.clone();
        t.swap(i, i + 1);
        assert!(decode_recovery_key(std::str::from_utf8(&t).unwrap()).is_err());
    }
}

#[test]
fn corrupted_checksum_is_reported_as_checksum() {
    let code = code_of(7).replace('-', "");
    let mut t = code.clone().into_bytes();
    let last = t.len() - 1;
    t[last] = if t[last] == b'0' { b'1' } else { b'0' };
    assert_eq!(
        decode_recovery_key(std::str::from_utf8(&t).unwrap()),
        Err(RecoveryError::Checksum)
    );
}

#[test]
fn malformed_codes_are_rejected() {
    let code = code_of(7).replace('-', "");
    assert_eq!(decode_recovery_key(""), Err(RecoveryError::Malformed));
    assert_eq!(
        decode_recovery_key(&code[..code.len() - 1]),
        Err(RecoveryError::Malformed)
    );
    assert_eq!(
        decode_recovery_key(&format!("{code}0")),
        Err(RecoveryError::Malformed)
    );
    // 'U' is not in the alphabet
    assert_eq!(
        decode_recovery_key(&code.replacen(&code[..1], "U", 1)),
        Err(RecoveryError::Malformed)
    );
    // non-zero pad bits in the 52nd symbol are non-canonical
    let mut t = code.clone().into_bytes();
    t[51] = b'1'; // 1 data bit would be 'G' or '0'; 0b00001 sets a pad bit
    assert_eq!(
        decode_recovery_key(std::str::from_utf8(&t).unwrap()),
        Err(RecoveryError::Malformed)
    );
}

#[test]
fn verify_retyped_accepts_only_the_same_key() {
    let (a, b) = (new_recovery_key().unwrap(), new_recovery_key().unwrap());
    let code = encode_recovery_key(&a);
    assert!(verify_retyped(&a, &code));
    assert!(verify_retyped(&a, &code.to_lowercase()));
    assert!(!verify_retyped(&b, &code));
    assert!(!verify_retyped(&a, "garbage"));
}

/// Fresh device: only the recovery wrapper, the wrapped vault key, a record and the typed
/// code survive; the old master password, header and every in-memory key are gone.
#[test]
fn restore_on_a_fresh_device_from_vault_data_and_code_alone() {
    // setup
    let ak = crate::new_account_key().unwrap();
    let vk = new_vault_key().unwrap();
    let rec = new_recovery_key().unwrap();
    let code = encode_recovery_key(&rec);
    let recovery_blob = wrap_account_key(&ak, &Wrapper::Recovery(&rec)).unwrap();
    let vk_blob = wrap_vault_key(&ak, 0, b"vault", 0, &vk).unwrap();
    let record = seal(&vk, 0, b"rec-1", b"secret item").unwrap();
    drop((ak, vk, rec));

    // restore
    let r = restore(&recovery_blob, &code, "a brand new password", fast()).unwrap();
    let vk = unwrap_vault_key(&r.account_key, b"vault", 0, &vk_blob).unwrap();
    assert_eq!(&**open(&vk, b"rec-1", &record).unwrap().1, b"secret item");

    // the new master password now opens the same account key
    let w = Wrapper::Master {
        password: "a brand new password",
        header: &r.master_header,
    };
    assert_eq!(
        unwrap_account_key(&r.master_wrapper, &w).unwrap(),
        r.account_key
    );

    // recovery key rotated: the new code opens the new wrapper, the old code does not
    let new_rec = decode_recovery_key(&r.recovery_code).unwrap();
    assert_eq!(
        unwrap_account_key(&r.recovery_wrapper, &Wrapper::Recovery(&new_rec)).unwrap(),
        r.account_key
    );
    assert_ne!(*r.recovery_code, *code);
    assert!(matches!(
        restore(&r.recovery_wrapper, &code, "x", fast()),
        Err(RecoveryError::Crypto)
    ));
}

#[test]
fn restore_fails_closed() {
    let ak = crate::new_account_key().unwrap();
    let rec = new_recovery_key().unwrap();
    let blob = wrap_account_key(&ak, &Wrapper::Recovery(&rec)).unwrap();
    let code = encode_recovery_key(&rec);

    // another vault's valid code
    let other = encode_recovery_key(&new_recovery_key().unwrap());
    assert!(matches!(
        restore(&blob, &other, "pw", fast()),
        Err(RecoveryError::Crypto)
    ));
    // typo in the code never reaches the wrapper
    let typo = code.replacen(&code[..1], if code.starts_with('1') { "2" } else { "1" }, 1);
    assert!(matches!(
        restore(&blob, &typo, "pw", fast()),
        Err(RecoveryError::Checksum | RecoveryError::Malformed)
    ));
    // tampered wrapper
    let mut bad = blob.clone();
    bad[10] ^= 1;
    assert!(matches!(
        restore(&bad, &code, "pw", fast()),
        Err(RecoveryError::Crypto)
    ));
}

/// SR-7: the recovery wrapper holds nothing that opens it besides the key itself.
#[test]
fn wrapper_does_not_contain_the_key_or_code() {
    let rec = Key::from_bytes([0x5a; 32]);
    let blob = wrap_account_key(&Key::from_bytes([1; 32]), &Wrapper::Recovery(&rec)).unwrap();
    assert!(!blob.windows(32).any(|w| w == rec.expose()));
}
