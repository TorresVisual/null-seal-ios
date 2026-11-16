#![allow(clippy::unwrap_used)]

use super::*;

const NOW: u64 = 1_800_000_000_000;

#[test]
fn login_candidates_carry_every_url_and_mode_but_no_secrets() {
    let pw = "correct horse battery staple 42!";
    let (mut setup, code) = begin_setup(
        Store::open_in_memory().unwrap(),
        pw,
        KdfParams::new(19 * 1024, 2, 1).unwrap(),
    )
    .unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    let f = LoginFields {
        title: "Bank".into(),
        username: "me".into(),
        password: "bank-pw".into(),
        url: "https://bank.com".into(),
        notes: String::new(),
    };
    let id = a.save_login(None, &f, NOW + 1).unwrap();
    let gone = a.save_login(None, &f, NOW + 2).unwrap();
    a.delete_login(&gone, NOW + 3).unwrap();

    assert_eq!(
        a.login_candidates().unwrap(),
        vec![Candidate {
            id,
            title: "Bank".into(),
            username: "me".into(),
            urls: vec![("https://bank.com".into(), None)],
            totp: false,
        }]
    );
    a.lock();
    assert!(
        a.login_candidates().is_err(),
        "locked is an error, not an empty list"
    );
}

#[test]
fn a_login_gives_its_totp_code_and_candidates_say_whether_it_has_one() {
    let (mut setup, code) = begin_setup(
        Store::open_in_memory().unwrap(),
        "correct horse battery staple 42!",
        KdfParams::new(19 * 1024, 2, 1).unwrap(),
    )
    .unwrap();
    let mut a = setup.confirm(&code, NOW).unwrap();
    let f = LoginFields {
        title: "Bank".into(),
        username: "me".into(),
        password: "pw".into(),
        url: "https://bank.com".into(),
        notes: String::new(),
    };
    let mut ids = vec![];
    // base32("12345678901234567890"): RFC 6238 Appendix B, SHA-1, t=59 is 94287082.
    for (n, totp) in [
        None,
        Some("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"),
        Some("otpauth://hotp/x?secret=GEZDGNBVGY3TQOJQ&counter=1"),
        Some("steam://GEZDGNBVGY3TQOJQ"),
    ]
    .into_iter()
    .enumerate()
    {
        let id = a.save_login(None, &f, NOW + n as u64).unwrap();
        let mut p = a.session.open_record(&a.live(&id).unwrap()).unwrap();
        p.data.totp = totp.map(str::to_owned);
        let old = a.session.open_record(&a.live(&id).unwrap()).unwrap();
        a.write(&id, Some(&old), Some(p), NOW + 10 + n as u64)
            .unwrap();
        ids.push(id);
    }
    let has: Vec<_> = ids
        .iter()
        .map(|id| a.login_totp(id, 59_000).unwrap().is_some())
        .collect();
    assert_eq!(has, [false, true, false, false]);
    let mut by_id: Vec<_> = a
        .login_candidates()
        .unwrap()
        .into_iter()
        .map(|c| (c.id, c.totp))
        .collect();
    by_id.sort();
    let mut want: Vec<_> = ids.iter().cloned().zip(has).collect();
    want.sort();
    assert_eq!(by_id, want);

    let t = a.login_totp(&ids[1], 59_000).unwrap().unwrap();
    assert_eq!((t.code.as_str(), t.remaining, t.period), ("287082", 1, 30));
    assert_eq!(
        a.login_totp(&ids[1], 60_000).unwrap().unwrap().remaining,
        30
    );
    assert!(a.login_totp("nope", 0).is_err());
    a.lock();
    assert!(a.login_totp(&ids[1], 59_000).is_err());
}
