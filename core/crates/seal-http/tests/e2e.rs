//! End-to-end sync harness (#39): two headless clients against the real relay Worker running
//! under local wrangler (miniflare + D1), no mocks in the path.
//!
//! `#[ignore]` so a plain `cargo test` stays offline; CI and `pnpm relay:e2e` run
//! `cargo test -p seal-http --test e2e -- --ignored`. Needs `pnpm install` at the repo root.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use core_crypto::KdfParams;
use core_store::Store;
use core_sync::enroll::Joiner;
use core_sync::{Device, Transport, register_first_device};
use seal_core::account::{Account, ItemSummary, LoginFields, begin_setup};
use seal_http::Http;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const PW: &str = "correct horse battery staple 42!";
const TOKEN: &str = "e2e-setup-token";

fn now() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A local relay: migrated D1 in a temp dir, `wrangler dev` on a free port. Killed on drop.
struct Relay {
    child: Child,
    url: String,
    dir: PathBuf,
}

impl Relay {
    fn start() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../relay");
        let wrangler = root.join("node_modules/wrangler/bin/wrangler.js");
        assert!(
            wrangler.exists(),
            "run `corepack pnpm install` at the repo root first"
        );
        // tests run in parallel: one state directory (and port) per relay
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("null-seal-e2e-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let run = |args: &[&str]| {
            let mut c = Command::new("node");
            c.arg(&wrangler)
                .args(args)
                .arg("--persist-to")
                .arg(&dir)
                .current_dir(&root);
            c
        };
        let st = run(&["d1", "migrations", "apply", "DB", "--local"])
            .stdout(Stdio::null())
            .status()
            .unwrap();
        assert!(st.success(), "applying relay migrations failed");
        let child = run(&[
            "dev",
            "--local",
            "--ip",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--var",
            &format!("SETUP_TOKEN:{TOKEN}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
        let relay = Self {
            child,
            url: format!("http://127.0.0.1:{port}"),
            dir,
        };
        let http = Http::new(&relay.url).unwrap();
        for _ in 0..120 {
            let req = core_sync::Request {
                method: "GET",
                path: "/v1/pull".into(),
                headers: vec![],
                body: vec![],
            };
            if http.send(&req).is_ok_and(|r| r.status == 401) {
                return relay;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        panic!("wrangler dev did not become ready");
    }

    fn http(&self) -> Http {
        Http::new(&self.url).unwrap()
    }
}

impl Drop for Relay {
    fn drop(&mut self) {
        // wrangler spawns workerd; kill the whole tree.
        if cfg!(windows) {
            let _ = Command::new("taskkill")
                .args(["/T", "/F", "/PID", &self.child.id().to_string()])
                .output();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn login(title: &str, password: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me@example.com".into(),
        password: password.into(),
        url: "https://example.com".into(),
        notes: String::new(),
    }
}

/// Both clients' visible state, for failure messages.
fn state(a: &Account, b: &Account) -> String {
    let list = |x: &Account| {
        format!(
            "{:?}",
            x.list_items().map(|v| v
                .into_iter()
                .map(|i: ItemSummary| (i.title, i.id))
                .collect::<Vec<_>>())
        )
    };
    format!(
        "\n  A ({}): {}\n  B ({}): {}",
        a.device_id(),
        list(a),
        b.device_id(),
        list(b)
    )
}

fn titles(a: &Account) -> Vec<String> {
    a.list_items()
        .unwrap()
        .into_iter()
        .map(|i| i.title)
        .collect()
}

#[test]
#[ignore = "needs wrangler (pnpm install); run with --ignored"]
fn two_clients_create_edit_delete_and_enroll_through_the_real_relay() {
    let relay = Relay::start();
    let http = relay.http();

    // Device A: set up the vault and register as the relay's first device.
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = setup.confirm(&code, now()).unwrap();
    a.register_with_relay(&http, &relay.url, TOKEN).unwrap();
    // the setup token only works once
    let stranger = Device {
        id: "late".into(),
        seed: core_crypto::Key::random().unwrap(),
    };
    assert!(register_first_device(&http, &stranger, TOKEN).is_err());

    let mail = a.save_login(None, &login("Mail", "pw-one"), now()).unwrap();
    a.save_login(None, &login("Bank", "pw-two"), now()).unwrap();
    a.sync(&http, now()).unwrap();

    // Enroll device B through the relay.
    let (offer, enroll_code) = a.enroll_offer(&http, now()).unwrap();
    let joiner = Joiner::new(&enroll_code).unwrap();
    joiner.send_request(&http).unwrap();
    let req = a
        .enroll_poll(&offer, &http, now())
        .unwrap()
        .expect("request should be waiting");
    a.enroll_approve(&offer, &req, &http, now()).unwrap();
    let payload = joiner
        .poll_result(&http)
        .unwrap()
        .expect("approved payload");
    assert!(
        joiner.poll_result(&http).unwrap().is_none(),
        "result is one-shot"
    );
    let mut b = Account::complete_join(
        Store::open_in_memory().unwrap(),
        &joiner,
        &payload,
        &relay.url,
    )
    .unwrap();
    b.unlock(PW, now()).unwrap();

    // create propagates
    b.sync(&http, now()).unwrap();
    assert_eq!(titles(&b), ["Bank", "Mail"], "{}", state(&a, &b));

    // edit propagates
    a.save_login(Some(&mail), &login("Mail", "pw-rotated"), now())
        .unwrap();
    a.sync(&http, now()).unwrap();
    b.sync(&http, now()).unwrap();
    assert_eq!(
        b.get_login(&mail).unwrap().password,
        "pw-rotated",
        "{}",
        state(&a, &b)
    );

    // delete propagates, in the other direction
    b.delete_login(&mail, now()).unwrap();
    b.sync(&http, now()).unwrap();
    a.sync(&http, now()).unwrap();
    assert_eq!(titles(&a), ["Bank"], "{}", state(&a, &b));

    // concurrent edits of one record converge on the later one
    let bank = b.list_items().unwrap()[0].id.clone();
    a.save_login(Some(&bank), &login("Bank", "from-a"), now())
        .unwrap();
    std::thread::sleep(Duration::from_millis(5));
    b.save_login(Some(&bank), &login("Bank", "from-b"), now())
        .unwrap();
    a.sync(&http, now()).unwrap();
    b.sync(&http, now()).unwrap();
    a.sync(&http, now()).unwrap();
    assert_eq!(
        a.get_login(&bank).unwrap().password,
        "from-b",
        "{}",
        state(&a, &b)
    );
    assert_eq!(
        b.get_login(&bank).unwrap().password,
        "from-b",
        "{}",
        state(&a, &b)
    );
}

/// Enroll a new unlocked device through `by`, over the real relay.
fn enroll(http: &Http, url: &str, by: &Account) -> Account {
    let (offer, code) = by.enroll_offer(http, now()).unwrap();
    let joiner = Joiner::new(&code).unwrap();
    joiner.send_request(http).unwrap();
    let req = by.enroll_poll(&offer, http, now()).unwrap().unwrap();
    by.enroll_approve(&offer, &req, http, now()).unwrap();
    let payload = joiner.poll_result(http).unwrap().unwrap();
    let mut d =
        Account::complete_join(Store::open_in_memory().unwrap(), &joiner, &payload, url).unwrap();
    d.unlock(PW, now()).unwrap();
    d
}

#[test]
#[ignore = "needs wrangler (pnpm install); run with --ignored"]
fn revoking_a_device_rotates_keys_through_the_real_relay() {
    let relay = Relay::start();
    let http = relay.http();
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = setup.confirm(&code, now()).unwrap();
    a.register_with_relay(&http, &relay.url, TOKEN).unwrap();
    let bank = a.save_login(None, &login("Bank", "pw-1"), now()).unwrap();
    a.sync(&http, now()).unwrap();
    let mut b = enroll(&http, &relay.url, &a);
    b.sync(&http, now()).unwrap();
    let mut c = enroll(&http, &relay.url, &a);
    c.sync(&http, now()).unwrap();
    a.sync(&http, now()).unwrap();

    let list = a.list_devices(&http, now()).unwrap();
    assert_eq!(list.len(), 3);
    assert!(list.iter().all(|d| d.verified), "{list:?}");

    let (rev, new_code) = a
        .begin_revocation(PW, vec![c.device_id().to_owned()])
        .unwrap();
    let report = a.finish_revocation(rev, &new_code, &http, now()).unwrap();
    assert_eq!(
        (report.revoked, report.rekeyed, report.synced),
        (1, 2, true)
    );

    a.save_login(Some(&bank), &login("Bank", "pw-2"), now())
        .unwrap();
    a.sync(&http, now()).unwrap();
    assert!(
        c.sync(&http, now()).is_err(),
        "revoked device is locked out"
    );
    b.sync(&http, now()).unwrap();
    assert_eq!(b.get_login(&bank).unwrap().password, "pw-2");
    assert_eq!(a.list_devices(&http, now()).unwrap().len(), 2);
}

#[test]
#[ignore = "needs wrangler (pnpm install); run with --ignored"]
fn a_restored_device_rejoins_the_real_relay_with_no_device_left() {
    use seal_core::account::BackupSecret;
    let relay = Relay::start();
    let http = relay.http();
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = setup.confirm(&code, now()).unwrap();
    a.register_with_relay(&http, &relay.url, TOKEN).unwrap();
    a.save_login(None, &login("Bank", "pw-1"), now()).unwrap();
    a.sync(&http, now()).unwrap();
    let file = a.backup(now()).unwrap();
    a.save_login(None, &login("Mail", "pw-2"), now()).unwrap();
    a.sync(&http, now()).unwrap();
    drop(a); // no enrolled device is left

    let mut r = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Password(PW),
        now(),
    )
    .unwrap();
    r.unlock(PW, now()).unwrap();
    r.rejoin_relay(&http, &relay.url, now()).unwrap();
    r.sync(&http, now()).unwrap();
    assert_eq!(titles(&r), ["Bank", "Mail"]);

    // a relay that never held this account refuses the same proof
    let other = Relay::start();
    let mut r2 = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Password(PW),
        now(),
    )
    .unwrap();
    r2.unlock(PW, now()).unwrap();
    assert!(r2.rejoin_relay(&other.http(), &other.url, now()).is_err());
    assert_eq!(r2.relay_url(), None);
}

#[test]
#[ignore = "needs wrangler (pnpm install); run with --ignored"]
fn an_encrypted_backup_goes_through_the_real_relay_and_restores() {
    use seal_core::account::BackupSecret;
    let relay = Relay::start();
    let http = relay.http();
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut setup, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = setup.confirm(&code, now()).unwrap();
    let code = code.to_string();
    a.register_with_relay(&http, &relay.url, TOKEN).unwrap();
    a.save_login(None, &login("Bank", "pw-1"), now()).unwrap();

    let key = a.backup_to_relay(&http, now()).unwrap();
    assert_eq!(a.relay_backups(&http, now()).unwrap()[0].key, key);
    let file = a.download_relay_backup(&http, now(), &key).unwrap();
    let mut r = Account::restore(
        Store::open_in_memory().unwrap(),
        &file,
        &BackupSecret::Recovery(&code),
        now(),
    )
    .unwrap();
    r.reset_master_password(&code, PW, KdfParams::new(19 * 1024, 2, 1).unwrap())
        .unwrap();
    r.unlock(PW, now()).unwrap();
    assert_eq!(titles(&r), ["Bank"]);
}
