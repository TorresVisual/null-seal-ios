#![allow(clippy::unwrap_used)]

use super::*;
use std::collections::HashSet;

/// RNG that replays fixed draws, then errors.
fn fixed<const N: usize>(draws: [u32; N]) -> impl FnMut() -> Result<u32, Error> {
    let mut it = draws.into_iter();
    move || it.next().ok_or(Error::Rng)
}

#[test]
fn uniform_rejects_the_biased_tail() {
    // n=3: 2^32 = 3 * 1431655765 + 1, so only 0xFFFF_FFFF is in the biased zone.
    let mut rng = fixed([u32::MAX, u32::MAX, 7]);
    assert_eq!(uniform(3, &mut rng), Ok(1)); // both rejected, then 7 % 3
    assert_eq!(uniform(3, &mut rng), Err(Error::Rng)); // all three draws were consumed
    // n=2^31+1: draws >= n*1 are rejected, so 0xFFFF_FFFF is skipped, not folded onto 0.
    assert_eq!(uniform((1 << 31) + 1, &mut fixed([u32::MAX, 5])), Ok(5));
    // Largest accepted draw maps without wrapping.
    assert_eq!(uniform(3, &mut fixed([u32::MAX - 1])), Ok(2));
}

#[test]
fn uniform_is_roughly_flat() {
    let mut counts = [0u32; 6];
    for _ in 0..60_000 {
        counts[uniform(6, &mut os_u32).unwrap()] += 1;
    }
    // Expected 10_000 each, sigma ~ 91; 500 is > 5 sigma.
    assert!(
        counts.iter().all(|c| c.abs_diff(10_000) < 500),
        "{counts:?}"
    );
}

#[test]
fn password_honours_options() {
    for avoid in [false, true] {
        for (lower, upper, digits, symbols) in [
            (true, true, true, true),
            (true, false, false, false),
            (false, true, true, false),
            (false, false, true, true),
        ] {
            let o = PasswordOpts {
                length: 24,
                lower,
                upper,
                digits,
                symbols,
                min_digits: 3,
                min_symbols: 4,
                avoid_ambiguous: avoid,
            };
            for _ in 0..50 {
                let p = generate_password(&o).unwrap();
                let n = |set: &[u8]| p.bytes().filter(|b| set.contains(b)).count();
                assert_eq!(p.len(), 24);
                assert_eq!(n(LOWER) > 0, lower);
                assert_eq!(n(UPPER) > 0, upper);
                assert_eq!(n(DIGITS) > 0, digits);
                assert_eq!(n(SYMBOLS) > 0, symbols);
                if digits {
                    assert!(n(DIGITS) >= 3);
                }
                if symbols {
                    assert!(n(SYMBOLS) >= 4);
                }
                if avoid {
                    assert_eq!(n(AMBIGUOUS), 0);
                }
            }
        }
    }
}

#[test]
fn password_rejects_bad_options() {
    let ok = PasswordOpts::default();
    let bad = [
        PasswordOpts {
            lower: false,
            upper: false,
            digits: false,
            symbols: false,
            ..ok.clone()
        },
        PasswordOpts {
            length: 0,
            ..ok.clone()
        },
        PasswordOpts {
            length: MAX_PASSWORD_LEN + 1,
            ..ok.clone()
        },
        PasswordOpts {
            length: 3,
            ..ok.clone()
        }, // four classes need four characters
        PasswordOpts {
            length: 10,
            min_digits: 8,
            ..ok.clone()
        },
    ];
    for (i, o) in bad.iter().enumerate() {
        assert!(generate_password(o).is_err(), "case {i}");
    }
    assert!(generate_password(&PasswordOpts { length: 4, ..ok }).is_ok());
}

#[test]
fn password_pool_covers_whole_class() {
    // Every symbol and digit eventually appears (guards against truncated/skewed charsets).
    let o = PasswordOpts {
        length: 128,
        lower: false,
        upper: false,
        ..Default::default()
    };
    let seen: HashSet<u8> = (0..40)
        .flat_map(|_| generate_password(&o).unwrap().bytes().collect::<Vec<_>>())
        .collect();
    assert_eq!(seen.len(), DIGITS.len() + SYMBOLS.len());
}

#[test]
fn wordlist_is_the_eff_large_list() {
    let words: Vec<&str> = WORDS.lines().collect();
    assert_eq!(words.len(), 7776);
    assert_eq!(words.iter().collect::<HashSet<_>>().len(), 7776);
    assert!(
        words
            .iter()
            .all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'))
    );
}

#[test]
fn passphrase_honours_options() {
    let list: HashSet<&str> = WORDS.lines().collect();
    let o = PassphraseOpts {
        words: 5,
        separator: "::".into(),
        ..Default::default()
    };
    let p = generate_passphrase(&o).unwrap();
    let parts: Vec<&str> = p.split("::").collect();
    assert_eq!(parts.len(), 5);
    assert!(parts.iter().all(|w| list.contains(w)));

    let o = PassphraseOpts {
        capitalize: true,
        include_number: true,
        ..Default::default()
    };
    for _ in 0..50 {
        let p = generate_passphrase(&o).unwrap();
        assert!(p.split('-').count() >= 6); // list words may themselves contain '-'
        assert_eq!(p.chars().filter(char::is_ascii_digit).count(), 1);
        assert!(p.chars().next().unwrap().is_uppercase());
    }
    for words in [MIN_WORDS - 1, MAX_WORDS + 1] {
        assert!(
            generate_passphrase(&PassphraseOpts {
                words,
                ..Default::default()
            })
            .is_err()
        );
    }
}

#[test]
fn rng_failure_is_an_error_not_a_weak_secret() {
    assert_eq!(
        password_with(&PasswordOpts::default(), &mut fixed([1, 2, 3])),
        Err(Error::Rng)
    );
    assert_eq!(
        passphrase_with(&PassphraseOpts::default(), &mut fixed([1])),
        Err(Error::Rng)
    );
}

#[test]
fn estimator_ranks_known_weak_passwords_low() {
    for weak in [
        "password",
        "123456",
        "qwerty",
        "letmein",
        "iloveyou",
        "Password1",
        "abc123",
        "admin",
    ] {
        assert!(estimate(weak, &[]).score <= 1, "{weak}");
    }
    let strong = estimate(&generate_password(&PasswordOpts::default()).unwrap(), &[]);
    assert_eq!(strong.score, 4);
    let phrase = estimate(
        &generate_passphrase(&PassphraseOpts::default()).unwrap(),
        &[],
    );
    assert_eq!(phrase.score, 4);
    assert!(strong.guesses_log10 > estimate("password", &[]).guesses_log10);
}

#[test]
fn estimator_uses_user_inputs() {
    let plain = estimate("torresvisual2026", &[]);
    let known = estimate("torresvisual2026", &["torresvisual"]);
    assert!(known.guesses_log10 < plain.guesses_log10);
}
