//! Stand-in relay and "existing device" for the iOS simulator UI tests (#92).
//!
//! `ui_relay <out-dir>` serves the in-memory mock relay on a loopback port, holds a synthetic
//! vault with two logins, and approves the first join request it sees. It writes `relay` (the
//! address), `code` (the join code) and `password` (the master password) into `<out-dir>` once it
//! is ready, so the test can drive the app's real onboarding, unlock and sync. Test fixture only:
//! nothing here ships in the app.

#![allow(clippy::print_stderr)]

use core_crypto::KdfParams;
use core_store::Store;
use core_sync::mock::MockRelay;
use core_sync::{Request, Transport};
use seal_core::account::{LoginFields, begin_setup};
use std::error::Error;
use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{env, fs, thread};

const PASSWORD: &str = "correct horse battery staple 42!";
const HEADERS: [&str; 4] = ["x-device", "x-ts", "x-sig", "x-setup-token"];

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

/// Write via a rename so the test never reads a half-written file.
fn publish(dir: &Path, name: &str, text: &str) -> std::io::Result<()> {
    let tmp = dir.join(format!(".{name}"));
    fs::write(&tmp, text)?;
    fs::rename(tmp, dir.join(name))
}

/// One HTTP/1.1 request in, one response out, connection closed.
fn serve(relay: &MockRelay, mut conn: TcpStream) -> Result<(), Box<dyn Error>> {
    conn.set_nonblocking(false)?; // inherited from the listener on some platforms
    conn.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let (head_len, body_len) = loop {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&buf[..end]).to_lowercase();
            let len = head
                .lines()
                .find_map(|l| l.strip_prefix("content-length:"))
                .and_then(|v| v.trim().parse::<usize>().ok())
                .unwrap_or(0);
            break (end + 4, len);
        }
    };
    while buf.len() < head_len + body_len {
        let n = conn.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&chunk[..n]);
    }

    let head = String::from_utf8_lossy(&buf[..head_len]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next().unwrap_or_default().split(' ');
    let verb = first.next();
    let method = ["GET", "POST", "PUT", "DELETE"]
        .into_iter()
        .find(|m| Some(*m) == verb)
        .ok_or("unsupported method")?;
    let path = first.next().ok_or("no path")?.to_owned();
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .filter_map(|(k, v)| {
            let name = HEADERS.into_iter().find(|h| h.eq_ignore_ascii_case(k))?;
            Some((name, v.trim().to_owned()))
        })
        .collect();
    let body = buf[head_len..(head_len + body_len).min(buf.len())].to_vec();

    relay.now_ms.set(now_ms());
    let log = format!("{method} {path}");
    let res = relay
        .send(&Request {
            method,
            path,
            headers,
            body,
        })
        .map_err(|e| e.0)?;
    eprintln!("{log} -> {}", res.status); // shows in the CI log; no bodies, no headers
    write!(
        conn,
        "HTTP/1.1 {} -\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
        res.status,
        res.body.len()
    )?;
    conn.write_all(&res.body)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let dir = env::args().nth(1).ok_or("usage: ui_relay <out-dir>")?;
    let dir = Path::new(&dir);
    fs::create_dir_all(dir)?;

    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let url = format!("http://127.0.0.1:{}", listener.local_addr()?.port());

    // The existing device: set up, register with the relay, push two logins.
    let relay = MockRelay::new(now_ms());
    let params = KdfParams::new(19 * 1024, 2, 1)?;
    let (mut setup, recovery) = begin_setup(Store::open_in_memory()?, PASSWORD, params)?;
    let mut me = setup.confirm(&recovery, now_ms())?;
    me.register_with_relay(&relay, &url, "setup")?;
    for (title, username) in [("Bank", "alice"), ("Email", "alice@example.com")] {
        let fields = LoginFields {
            title: title.into(),
            username: username.into(),
            password: "hunter2-hunter2".into(),
            url: String::new(),
            notes: String::new(),
        };
        me.save_login(None, &fields, now_ms())?;
    }
    me.sync(&relay, now_ms())?;
    let (offer, code) = me.enroll_offer(&relay, now_ms())?;

    publish(dir, "password", PASSWORD)?;
    publish(dir, "code", &code)?;
    publish(dir, "relay", &url)?; // last: the script waits for this one

    let mut approved = false;
    loop {
        match listener.accept() {
            Ok((conn, _)) => {
                if let Err(e) = serve(&relay, conn) {
                    eprintln!("request failed: {e}"); // one bad request must not end the run
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(e.into()),
        }
        if !approved {
            relay.now_ms.set(now_ms());
            if let Some(req) = me.enroll_poll(&offer, &relay, now_ms())? {
                me.enroll_approve(&offer, &req, &relay, now_ms())?;
                approved = true;
                eprintln!("join approved");
            }
        }
    }
}
