#![allow(clippy::unwrap_used)]

use super::*;

fn fast() -> KdfParams {
    KdfParams::new(19 * 1024, 2, 1).unwrap() // OWASP floor, keeps debug-build tests quick
}

fn key(b: u8) -> Key {
    Key::from_bytes([b; 32])
}

#[test]
fn each_wrapper_opens_the_same_account_key_independently() {
    let ak = new_account_key().unwrap();
    let hdr = MasterHeader::new(fast()).unwrap();
    let (rec, dev) = (Key::random().unwrap(), Key::random().unwrap());
    let ws = [
        Wrapper::Master {
            password: "correct horse battery",
            header: &hdr,
        },
        Wrapper::Recovery(&rec),
        Wrapper::Device {
            key: &dev,
            device_id: b"dev-1",
        },
    ];
    for w in &ws {
        let blob = wrap_account_key(&ak, w).unwrap();
        assert_eq!(unwrap_account_key(&blob, w).unwrap(), ak);
        assert_eq!(envelope_key_gen(&blob).unwrap(), 0);
    }
}

#[test]
fn wrong_secret_fails_closed() {
    let ak = key(1);
    let hdr = MasterHeader::new(fast()).unwrap();
    let m = Wrapper::Master {
        password: "right",
        header: &hdr,
    };
    let blob = wrap_account_key(&ak, &m).unwrap();
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Master {
                password: "wrong",
                header: &hdr
            }
        )
        .is_err()
    );

    let (r1, r2) = (key(2), key(3));
    let blob = wrap_account_key(&ak, &Wrapper::Recovery(&r1)).unwrap();
    assert!(unwrap_account_key(&blob, &Wrapper::Recovery(&r2)).is_err());

    let (d1, d2) = (key(4), key(5));
    let blob = wrap_account_key(
        &ak,
        &Wrapper::Device {
            key: &d1,
            device_id: b"a",
        },
    )
    .unwrap();
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Device {
                key: &d2,
                device_id: b"a"
            }
        )
        .is_err()
    );
    // right key, other device id: context mismatch
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Device {
                key: &d1,
                device_id: b"b"
            }
        )
        .is_err()
    );
}

#[test]
fn master_header_is_bound_and_password_is_nfkc() {
    let ak = key(1);
    let hdr = MasterHeader::new(fast()).unwrap();
    let blob = wrap_account_key(
        &ak,
        &Wrapper::Master {
            password: "caf\u{e9}",
            header: &hdr,
        },
    )
    .unwrap();
    // decomposed e + combining acute normalises to the same password
    let same = Wrapper::Master {
        password: "cafe\u{301}",
        header: &hdr,
    };
    assert_eq!(unwrap_account_key(&blob, &same).unwrap(), ak);
    // unknown normalisation rule is refused
    let bad = MasterHeader { pw_norm: 2, ..hdr };
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Master {
                password: "caf\u{e9}",
                header: &bad
            }
        )
        .is_err()
    );
    // different salt (downgrade/swap attempt) fails
    let other = MasterHeader {
        salt: [0; SALT_LEN],
        ..hdr
    };
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Master {
                password: "caf\u{e9}",
                header: &other
            }
        )
        .is_err()
    );
}

#[test]
fn wrapper_kinds_are_not_interchangeable() {
    // same raw key used as recovery and as device key must not cross-open
    let k = key(9);
    let blob = wrap_account_key(&key(1), &Wrapper::Recovery(&k)).unwrap();
    assert!(
        unwrap_account_key(
            &blob,
            &Wrapper::Device {
                key: &k,
                device_id: b""
            }
        )
        .is_err()
    );
}

#[test]
fn tampered_envelope_is_rejected_at_every_byte() {
    let k = key(2);
    let w = Wrapper::Recovery(&k);
    let blob = wrap_account_key(&key(1), &w).unwrap();
    for i in 0..blob.len() {
        let mut t = blob.clone();
        t[i] ^= 1;
        assert!(
            unwrap_account_key(&t, &w).is_err(),
            "flip at byte {i} accepted"
        );
    }
    assert!(unwrap_account_key(&blob[..blob.len() - 1], &w).is_err());
    assert!(unwrap_account_key(&[], &w).is_err());
}

#[test]
fn unknown_version_or_suite_is_rejected_even_if_authentic() {
    let k = key(2);
    let ctx = context(&[b"x"]);
    let good = seal(&k, 7, &ctx, b"data").unwrap();
    assert_eq!(&**open(&k, &ctx, &good).unwrap().1, b"data");
    for (idx, val) in [(0, 2), (1, 2)] {
        // forge a blob that authenticates under the altered header, so only the version check can stop it
        let mut header = good[..HEADER_LEN].to_vec();
        header[idx] = val;
        let mut forged = header.clone();
        forged.extend(core_crypto::encrypt(&k, &aad(&header, &ctx), b"data").unwrap());
        assert!(
            open(&k, &ctx, &forged).is_err(),
            "header byte {idx}={val} accepted"
        );
        assert!(envelope_key_gen(&forged).is_err());
    }
}

#[test]
fn vault_keys_wrap_under_account_key() {
    let ak = key(1);
    let vk = new_vault_key().unwrap();
    let blob = wrap_vault_key(&ak, 3, b"vault-a", 1, &vk).unwrap();
    assert_eq!(envelope_key_gen(&blob).unwrap(), 3);
    assert_eq!(unwrap_vault_key(&ak, b"vault-a", 1, &blob).unwrap(), vk);
    assert!(unwrap_vault_key(&ak, b"vault-b", 1, &blob).is_err());
    assert!(unwrap_vault_key(&ak, b"vault-a", 2, &blob).is_err());
    assert!(unwrap_vault_key(&key(2), b"vault-a", 1, &blob).is_err());
}

#[test]
fn context_is_unambiguous() {
    assert_ne!(context(&[b"ab", b"c"]), context(&[b"a", b"bc"]));
}

#[test]
fn seal_to_needs_the_device_secret_and_the_binding() {
    let (sk, other) = (key(7), key(8));
    let pk = core_crypto::x25519_public(&sk);
    let blob = seal_to(&pk, b"ak", b"ctx", b"new keys").unwrap();
    assert_eq!(&*open_from(&sk, b"ak", b"ctx", &blob).unwrap(), b"new keys");
    assert!(
        open_from(&other, b"ak", b"ctx", &blob).is_err(),
        "other device"
    );
    assert!(
        open_from(&sk, b"other", b"ctx", &blob).is_err(),
        "no binding secret"
    );
    assert!(
        open_from(&sk, b"ak", b"other", &blob).is_err(),
        "wrong context"
    );
    let mut bad = blob.clone();
    bad[40] ^= 1;
    assert!(open_from(&sk, b"ak", b"ctx", &bad).is_err());
    assert!(open_from(&sk, b"ak", b"ctx", &blob[..20]).is_err());
}
