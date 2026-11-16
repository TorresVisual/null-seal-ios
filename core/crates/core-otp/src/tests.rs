#![allow(clippy::unwrap_used)]

use super::*;

const SHA1_KEY: &[u8] = b"12345678901234567890";
const SHA256_KEY: &[u8] = b"12345678901234567890123456789012";
const SHA512_KEY: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

#[test]
fn rfc4226_appendix_d_hotp() {
    let want = [
        "755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871",
        "520489",
    ];
    for (counter, code) in want.iter().enumerate() {
        let got = hotp(Algorithm::Sha1, SHA1_KEY, counter as u64, 6).unwrap();
        assert_eq!(&*got, code, "counter {counter}");
    }
}

#[test]
fn rfc6238_appendix_b_totp() {
    // (time, SHA-1, SHA-256, SHA-512), 8 digits, 30 s step.
    let rows: [(u64, &str, &str, &str); 6] = [
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];
    for (t, s1, s256, s512) in rows {
        for (alg, key, want) in [
            (Algorithm::Sha1, SHA1_KEY, s1),
            (Algorithm::Sha256, SHA256_KEY, s256),
            (Algorithm::Sha512, SHA512_KEY, s512),
        ] {
            assert_eq!(&*totp(alg, key, t, 30, 8).unwrap(), want, "{alg:?} t={t}");
        }
    }
}

#[test]
fn leading_zeros_are_kept() {
    // RFC 6238 SHA-1 t=1111111109 is 07081804 at 8 digits; 6 digits is its low part.
    assert_eq!(
        &*totp(Algorithm::Sha1, SHA1_KEY, 1_111_111_109, 30, 6).unwrap(),
        "081804"
    );
}

#[test]
fn bad_params_are_rejected() {
    for d in [0, 5, 9] {
        assert!(hotp(Algorithm::Sha1, SHA1_KEY, 0, d).is_err());
    }
    assert!(hotp(Algorithm::Sha1, b"", 0, 6).is_err());
    assert!(totp(Algorithm::Sha1, SHA1_KEY, 0, 0, 6).is_err());
    assert!(totp(Algorithm::Sha1, SHA1_KEY, 0, MAX_PERIOD + 1, 6).is_err());
}

// base32("12345678901234567890")
const B32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

#[test]
fn uri_full_totp() {
    let uri = format!(
        "otpauth://totp/ACME%20Co:john.doe@example.com?secret={B32}&issuer=ACME%20Co\
         &algorithm=SHA256&digits=8&period=60"
    );
    let o = Otp::from_uri(&uri).unwrap();
    assert_eq!(o.issuer.as_deref(), Some("ACME Co"));
    assert_eq!(o.account, "john.doe@example.com");
    assert_eq!(o.algorithm, Algorithm::Sha256);
    assert_eq!(o.digits, 8);
    assert_eq!(o.kind, Kind::Totp { period: 60 });
    assert_eq!(
        o.code(1_234_567_890).unwrap(),
        totp(Algorithm::Sha256, SHA1_KEY, 1_234_567_890, 60, 8).unwrap()
    );
}

#[test]
fn uri_defaults_and_label_forms() {
    let o = Otp::from_uri(&format!("otpauth://totp/alice?secret={B32}")).unwrap();
    assert_eq!((o.issuer, o.account.as_str()), (None, "alice"));
    assert_eq!((o.algorithm, o.digits), (Algorithm::Sha1, 6));
    assert_eq!(o.kind, Kind::Totp { period: 30 });

    // Issuer only in the label prefix, escaped colon, lowercase+padded+spaced secret, odd casing.
    let lower = B32.to_lowercase();
    let o = Otp::from_uri(&format!(
        "OtpAuth://TOTP/Example%3Aalice%40x.org?secret={}%20{}===&Digits=7",
        &lower[..16],
        &lower[16..]
    ))
    .unwrap();
    assert_eq!(o.issuer.as_deref(), Some("Example"));
    assert_eq!(o.account, "alice@x.org");
    assert_eq!(o.digits, 7);
    assert_eq!(
        o.code(59).unwrap(),
        hotp(Algorithm::Sha1, SHA1_KEY, 1, 7).unwrap()
    );

    // issuer parameter wins over the label prefix; unknown params ignored.
    let o = Otp::from_uri(&format!(
        "otpauth://totp/Old:bob?secret={B32}&issuer=New&image=http%3A%2F%2Fx"
    ))
    .unwrap();
    assert_eq!(o.issuer.as_deref(), Some("New"));
    assert_eq!(o.account, "bob");
}

#[test]
fn uri_hotp() {
    let o = Otp::from_uri(&format!("otpauth://hotp/Svc:me?secret={B32}&counter=7")).unwrap();
    assert_eq!(o.kind, Kind::Hotp { counter: 7 });
    assert_eq!(&*o.code(0).unwrap(), "162583"); // RFC 4226 count 7
    assert!(Otp::from_uri(&format!("otpauth://hotp/x?secret={B32}")).is_err());
}

#[test]
fn uri_rejects_malformed() {
    for bad in [
        "",
        "https://totp/x?secret=GEZDGNBV",
        "otpauth://totp/x",
        "otpauth://totp/x?secret=",
        "otpauth://totp/x?secret=!!!!",
        "otpauth://foo/x?secret=GEZDGNBV",
        "otpauth://totp/x?secret=GEZDGNBV&digits=5",
        "otpauth://totp/x?secret=GEZDGNBV&digits=9",
        "otpauth://totp/x?secret=GEZDGNBV&digits=six",
        "otpauth://totp/x?secret=GEZDGNBV&period=0",
        "otpauth://totp/x?secret=GEZDGNBV&algorithm=MD5",
        "otpauth://totp/x%zz?secret=GEZDGNBV",
        "otpauth://totp/x%?secret=GEZDGNBV",
        "otpauth://totp/x%ff?secret=GEZDGNBV",
    ] {
        assert!(Otp::from_uri(bad).is_err(), "{bad}");
    }
}

#[test]
fn debug_and_errors_do_not_leak_secret() {
    let o = Otp::from_uri(&format!("otpauth://totp/x?secret={B32}")).unwrap();
    assert!(!format!("{o:?}").contains(B32));
    let e = Otp::from_uri(&format!("otpauth://totp/x?secret={B32}&digits=99")).unwrap_err();
    assert!(!format!("{e} {e:?}").contains(B32));
}

#[test]
fn base32_known_answers() {
    // RFC 4648 section 10
    for (plain, enc) in [
        ("f", "MY======"),
        ("fo", "MZXQ===="),
        ("foobar", "MZXW6YTBOI======"),
    ] {
        assert_eq!(base32_decode(enc).unwrap(), plain.as_bytes());
    }
}

#[test]
fn stored_totp_is_a_uri_or_a_bare_secret_and_nothing_else() {
    // RFC 6238 Appendix B, SHA-1 at t=59: 94287082, so 287082 at 6 digits.
    for stored in [
        B32.to_owned(),
        format!("  {} \n", B32.to_lowercase()),
        format!("otpauth://totp/x?secret={B32}"),
    ] {
        let o = Otp::parse(&stored).unwrap();
        assert_eq!(&*o.code(59).unwrap(), "287082", "{stored:?}");
        assert_eq!((o.remaining(59), o.remaining(60)), (Some(1), Some(30)));
    }
    assert!(Otp::parse("steam://ABC").is_err());
    // A bare secret is only base32: nothing in it is read as a URI parameter.
    assert!(Otp::parse(&format!("{B32}&period=1&digits=8")).is_err());
    assert!(Otp::parse(&format!("{B32}#x")).is_err());
    assert!(Otp::parse("not base32!").is_err());
    assert!(Otp::parse("").is_err());
    let hotp = Otp::parse(&format!("otpauth://hotp/x?secret={B32}&counter=1")).unwrap();
    assert_eq!(hotp.remaining(0), None);
}

/// A QR code of `text` as grayscale pixels: `scale` px per module, 4-module quiet zone.
fn qr_pixels(text: &str, scale: usize) -> (usize, usize, Vec<u8>) {
    let code = qrcode::QrCode::new(text).unwrap();
    let n = code.width();
    let side = (n + 8) * scale;
    let colors = code.to_colors();
    let mut px = vec![255u8; side * side];
    for (i, c) in colors.iter().enumerate() {
        if *c == qrcode::Color::Dark {
            let (mx, my) = ((i % n + 4) * scale, (i / n + 4) * scale);
            for y in my..my + scale {
                px[y * side + mx..y * side + mx + scale].fill(0);
            }
        }
    }
    (side, side, px)
}

#[test]
fn qr_image_gives_the_uri_and_the_reference_code() {
    // The RFC 6238 secret, so the code can be checked against the published value.
    let uri =
        format!("otpauth://totp/ACME%20Co:john@example.com?secret={B32}&issuer=ACME%20Co&digits=8");
    for scale in [3, 6] {
        let (w, h, px) = qr_pixels(&uri, scale);
        let text = decode_qr(w, h, &px).unwrap();
        assert_eq!(&*text, &uri);
        let o = Otp::parse(&text).unwrap();
        assert_eq!(&*o.code(59).unwrap(), "94287082");
        assert_eq!(o.label(), "ACME Co (john@example.com)");
    }
}

#[test]
fn qr_errors_are_clean() {
    assert_eq!(
        decode_qr(8, 8, &[0; 10]),
        Err(Error::Qr("pixel buffer does not match the image size"))
    );
    assert!(decode_qr(64, 64, &[255; 64 * 64]).is_err());
    assert!(decode_qr(usize::MAX, 2, &[]).is_err());
}

#[test]
fn label_uses_whatever_parts_exist() {
    let l = |s: &str| Otp::parse(s).unwrap().label();
    assert_eq!(
        l(&format!("otpauth://totp/Svc:me?secret={B32}")),
        "Svc (me)"
    );
    assert_eq!(l(&format!("otpauth://totp/me?secret={B32}")), "me");
    assert_eq!(
        l(&format!("otpauth://totp/?secret={B32}&issuer=Svc")),
        "Svc"
    );
    assert_eq!(l(B32), "");
}

/// Built with an independent protobuf encoder: ACME (SHA-1, 6 digits), bob (SHA-256, 8 digits),
/// an HOTP account and an MD5 account.
const MIGRATION: &str = "otpauth-migration://offline?data=Cj8KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEhhBQ01FIENvOmpvaG5AZXhhbXBsZS5jb20aB0FDTUUgQ28gASgBMAIKLwogMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTISA2JvYhoAIAIoAjACCi4KFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEglob3RwLWFjY3QaA09sZCABKAEwATgBCisKFDEyMzQ1Njc4OTAxMjM0NTY3ODkwEghtZDUtYWNjdBoDT2xkIAQoATACEAEYASAAKMDEBw%3D%3D";

#[test]
fn migration_link_gives_the_time_based_accounts_and_counts_the_rest() {
    assert!(is_migration(MIGRATION));
    let m = parse_migration(MIGRATION).unwrap();
    assert_eq!((m.uris.len(), m.skipped), (2, 2));

    let acme = Otp::parse(&m.uris[0]).unwrap();
    assert_eq!(acme.label(), "ACME Co (john@example.com)");
    assert_eq!(&*acme.code(59).unwrap(), "287082"); // RFC 6238, SHA-1

    let bob = Otp::parse(&m.uris[1]).unwrap();
    assert_eq!((bob.label().as_str(), bob.digits), ("bob", 8));
    assert_eq!(&*bob.code(59).unwrap(), "46119246"); // RFC 6238, SHA-256
}

#[test]
fn migration_data_that_is_damaged_is_rejected_whole() {
    let data = MIGRATION.split("data=").nth(1).unwrap();
    for bad in [
        "otpauth-migration://offline".to_owned(),
        "otpauth-migration://offline?data=".to_owned(),
        "otpauth-migration://offline?data=!!!!".to_owned(),
        // cut off mid-entry
        format!("otpauth-migration://offline?data={}", &data[..40]),
        "https://example.com/?data=AAAA".to_owned(),
    ] {
        assert!(parse_migration(&bad).is_err(), "{bad}");
    }
    assert!(!is_migration("otpauth://totp/x?secret=GEZDGNBV"));
}

#[test]
fn only_a_plain_scheme_name_is_echoed_for_other_links() {
    for (text, shown) in [
        (MIGRATION, "otpauth-migration"),
        ("steam://ABCDEFGH", "steam"),
        ("HTTPS://x", "https"),
        ("a b c://secret", "?"),
    ] {
        assert_eq!(
            Otp::parse(text).unwrap_err(),
            Error::UnsupportedScheme(shown.into()),
            "{text}"
        );
    }
}

#[test]
fn migration_qr_round_trips() {
    let (w, h, px) = qr_pixels(MIGRATION, 3);
    let text = decode_qr(w, h, &px).unwrap();
    assert_eq!(parse_migration(&text).unwrap().uris.len(), 2);
}
