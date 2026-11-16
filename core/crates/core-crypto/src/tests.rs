#![allow(clippy::unwrap_used)]

use super::*;

fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key(b: u8) -> Key {
    Key::from_bytes([b; KEY_LEN])
}

/// draft-irtf-cfrg-xchacha-03 appendix A.3.1.
#[test]
fn xchacha20poly1305_known_answer() {
    let k = Key::from_bytes((0x80..=0x9f).collect::<Vec<u8>>().try_into().unwrap());
    let nonce: [u8; NONCE_LEN] = (0x40..=0x57).collect::<Vec<u8>>().try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expect = unhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb
         731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452
         2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9
         21f9664c97637da9768812f615c68b13b52e
         c0875924c1c7987947deafd8780acf49",
    );
    let blob = encrypt_with_nonce(&k, nonce, &aad, pt).unwrap();
    assert_eq!(&blob[..NONCE_LEN], nonce);
    assert_eq!(&blob[NONCE_LEN..], expect);
    assert_eq!(&**decrypt(&k, &aad, &blob).unwrap(), pt);
}

#[test]
fn aead_roundtrip_and_fresh_nonces() {
    let k = key(7);
    let a = encrypt(&k, b"ctx", b"hello").unwrap();
    let b = encrypt(&k, b"ctx", b"hello").unwrap();
    assert_eq!(a.len(), NONCE_LEN + 5 + TAG_LEN);
    assert_ne!(a[..NONCE_LEN], b[..NONCE_LEN]);
    assert_eq!(&**decrypt(&k, b"ctx", &a).unwrap(), b"hello");
}

#[test]
fn aead_fails_closed() {
    let k = key(7);
    let blob = encrypt(&k, b"ctx", b"hello").unwrap();
    assert_eq!(decrypt(&key(8), b"ctx", &blob).unwrap_err(), Error);
    assert_eq!(decrypt(&k, b"other", &blob).unwrap_err(), Error);
    assert_eq!(decrypt(&k, b"ctx", &blob[..NONCE_LEN]).unwrap_err(), Error);
    assert_eq!(decrypt(&k, b"ctx", &[]).unwrap_err(), Error);
    for i in 0..blob.len() {
        let mut t = blob.clone();
        t[i] ^= 1;
        assert!(
            decrypt(&k, b"ctx", &t).is_err(),
            "flip at byte {i} accepted"
        );
    }
}

/// RFC 5869 test case 1 (first 32 of the 42 output bytes; HKDF-Expand is prefix-stable).
#[test]
fn hkdf_known_answer() {
    let k = hkdf(
        &[0x0b; 22],
        Some(&unhex("000102030405060708090a0b0c")),
        &unhex("f0f1f2f3f4f5f6f7f8f9"),
    )
    .unwrap();
    assert_eq!(
        k.expose().as_slice(),
        unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    );
    let other = hkdf(&[0x0b; 22], None, b"other").unwrap();
    assert!(k != other);
}

/// RFC 9106 section 5.3 (Argon2id, with secret and associated data), against the crate directly:
/// proves the dependency implements the standard. Costs are below our floor, so not via `argon2id`.
#[test]
fn argon2id_rfc9106_known_answer() {
    let params = argon2::ParamsBuilder::new()
        .m_cost(32)
        .t_cost(3)
        .p_cost(4)
        .data(argon2::AssociatedData::new(&[4; 12]).unwrap())
        .output_len(32)
        .build()
        .unwrap();
    let mut out = [0u8; 32];
    Argon2::new_with_secret(&[3; 8], Algorithm::Argon2id, Version::V0x13, params)
        .unwrap()
        .hash_password_into(&[1; 32], &[2; 16], &mut out)
        .unwrap();
    assert_eq!(
        out.as_slice(),
        unhex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
    );
}

#[test]
fn argon2id_wrapper_matches_crate_and_is_deterministic() {
    let (m, t, p) = (19 * 1024, 2, 1);
    let kp = KdfParams::new(m, t, p).unwrap();
    let a = argon2id(b"correct horse", &[9; 16], kp).unwrap();
    let mut direct = [0u8; 32];
    Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(m, t, p, Some(32)).unwrap(),
    )
    .hash_password_into(b"correct horse", &[9; 16], &mut direct)
    .unwrap();
    assert_eq!(a.expose(), &direct);
    assert!(a != argon2id(b"correct horse", &[10; 16], kp).unwrap());
    assert!(a != argon2id(b"battery staple", &[9; 16], kp).unwrap());
}

#[test]
fn kdf_params_are_bounded() {
    let mib = 1024;
    assert!(
        KdfParams::new(
            KdfParams::DEFAULT.m_kib(),
            KdfParams::DEFAULT.t(),
            KdfParams::DEFAULT.p()
        )
        .is_ok()
    );
    assert!(KdfParams::new(19 * mib, 2, 1).is_ok());
    assert!(KdfParams::new(1024 * mib, 10, 16).is_ok());
    for (m, t, p) in [
        (19 * mib - 1, 2, 1),
        (19 * mib, 1, 1),
        (19 * mib, 2, 0),
        (1024 * mib + 1, 2, 1),
        (19 * mib, 11, 1),
        (19 * mib, 2, 17),
    ] {
        assert!(KdfParams::new(m, t, p).is_err(), "{m} {t} {p}");
    }
    assert!(
        argon2id(
            b"pw",
            &[0; MIN_SALT_LEN - 1],
            KdfParams::new(19 * mib, 2, 1).unwrap()
        )
        .is_err()
    );
}

#[test]
fn keys_zeroize_and_hide() {
    fn zeroizes_on_drop<T: ZeroizeOnDrop>() {}
    zeroizes_on_drop::<Key>(); // the derive emits a Drop that zeroizes
    let mut k = key(0xAA);
    k.zeroize();
    assert_eq!(k.expose(), &[0u8; KEY_LEN]);
    assert_eq!(format!("{:?}", key(1)), "Key(<redacted>)");
    assert!(key(1) == key(1) && key(1) != key(2));
    assert!(Key::random().unwrap() != Key::random().unwrap());
}

#[test]
fn ct_eq_handles_lengths() {
    assert!(ct_eq(b"abc", b"abc"));
    assert!(!ct_eq(b"abc", b"abd"));
    assert!(!ct_eq(b"abc", b"ab"));
}

fn hex32(s: &str) -> [u8; 32] {
    unhex(s).try_into().unwrap()
}

/// RFC 8032 section 7.1, test 1 (empty message).
#[test]
fn ed25519_known_answer() {
    let seed = Key::from_bytes(hex32(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    ));
    let public = hex32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    assert_eq!(signing_public(&seed), public);
    let sig: [u8; 64] = unhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
         5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .try_into()
    .unwrap();
    assert_eq!(sign(&seed, b""), sig);
    assert!(verify(&public, b"", &sig));
    assert!(!verify(&public, b"x", &sig));
    let mut bad = sig;
    bad[0] ^= 1;
    assert!(!verify(&public, b"", &bad));
}

/// RFC 7748 section 6.1 public keys, then agreement and domain separation.
#[test]
fn x25519_agreement() {
    let a = Key::from_bytes(hex32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let b = Key::from_bytes(hex32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let (pa, pb) = (x25519_public(&a), x25519_public(&b));
    assert_eq!(
        pa,
        hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    );
    assert_eq!(
        pb,
        hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    );
    let k1 = x25519_shared(&a, &pb, b"label").unwrap();
    assert_eq!(k1, x25519_shared(&b, &pa, b"label").unwrap());
    assert_ne!(k1, x25519_shared(&a, &pb, b"other").unwrap());
    // a low-order point yields an all-zero shared secret and is refused
    assert!(x25519_shared(&a, &[0u8; 32], b"label").is_err());
}

#[test]
fn sha256_known_answer() {
    assert_eq!(
        sha256(b"abc"),
        hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn pbkdf2_sha256_rfc7914_known_answer() {
    // RFC 7914 section 11, c = 1 (first 32 of 64 bytes).
    let k = interop::pbkdf2_sha256(b"passwd", b"salt", 1).unwrap();
    assert_eq!(
        k.expose().as_slice(),
        unhex("55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc")
    );
    assert!(interop::pbkdf2_sha256(b"p", b"s", 0).is_err());
    assert!(interop::pbkdf2_sha256(b"p", b"s", interop::PBKDF2_MAX_ROUNDS + 1).is_err());
}

#[test]
fn hkdf_expand_rfc5869_known_answer() {
    // Test case 1 PRK and info; T(1) is the first 32 bytes of the OKM.
    let prk = Key::from_bytes(hex32(
        "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
    ));
    let k = interop::hkdf_expand(&prk, &unhex("f0f1f2f3f4f5f6f7f8f9")).unwrap();
    assert_eq!(
        k.expose().as_slice(),
        unhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf")
    );
}

#[test]
fn aes_cbc_hmac_roundtrip_and_fails_closed() {
    use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
    let (enc, mac, iv) = (key(1), key(2), [7u8; 16]);
    let ct = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc.expose(), &iv)
        .unwrap()
        .encrypt_padded_vec::<Pkcs7>(b"hello bitwarden");
    let tag = hmac(HmacAlg::Sha256, mac.expose(), &[&iv[..], &ct].concat()).unwrap();
    let open = |enc: &Key, mac: &Key, iv: &[u8], ct: &[u8], tag: &[u8]| {
        interop::aes256_cbc_hmac_decrypt(enc, mac, iv, ct, tag)
    };
    assert_eq!(
        &**open(&enc, &mac, &iv, &ct, &tag).unwrap(),
        b"hello bitwarden"
    );
    assert!(open(&key(3), &mac, &iv, &ct, &tag).is_err());
    assert!(open(&enc, &key(3), &iv, &ct, &tag).is_err());
    assert!(open(&enc, &mac, &iv[..15], &ct, &tag).is_err());
    assert!(open(&enc, &mac, &iv, &ct[1..], &tag).is_err());
    assert!(open(&enc, &mac, &iv, &ct, &tag[1..]).is_err());
    let mut bad = ct.clone();
    bad[0] ^= 1;
    assert!(open(&enc, &mac, &iv, &bad, &tag).is_err());
}
