#![allow(clippy::unwrap_used)]

//! Offline queue, backoff and quota handling (#43): induced network failures against the mock
//! relay. Edits made while the relay is unreachable or throttling stay queued, syncing pauses
//! with a visible status instead of hammering the relay, and everything lands once it is back.

use core_crypto::KdfParams;
use core_store::Store;
use core_sync::mock::MockRelay;
use core_sync::{Request, Response, SyncError, Transport, TransportError};
use seal_core::account::{Account, AccountError, LoginFields, begin_setup};
use std::cell::{Cell, RefCell};

const NOW: u64 = 1_800_000_000_000;
const PW: &str = "correct horse battery staple 42!";

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Up,
    Down,
    Quota,
}

/// The mock relay behind a switch; counts the requests that actually left the client.
struct Switch {
    relay: MockRelay,
    mode: Cell<Mode>,
    sent: RefCell<usize>,
}

impl Transport for Switch {
    fn send(&self, req: &Request) -> Result<Response, TransportError> {
        *self.sent.borrow_mut() += 1;
        match self.mode.get() {
            Mode::Up => self.relay.send(req),
            Mode::Down => Err(TransportError("down".into())),
            Mode::Quota => Ok(Response {
                status: 429,
                body: Vec::new(),
            }),
        }
    }
}

fn login(title: &str) -> LoginFields {
    LoginFields {
        title: title.into(),
        username: "me".into(),
        password: "pw".into(),
        url: String::new(),
        notes: String::new(),
    }
}

fn setup() -> (Account, Switch) {
    let t = Switch {
        relay: MockRelay::new(NOW),
        mode: Cell::new(Mode::Up),
        sent: RefCell::new(0),
    };
    let params = KdfParams::new(19 * 1024, 2, 1).unwrap();
    let (mut s, code) = begin_setup(Store::open_in_memory().unwrap(), PW, params).unwrap();
    let mut a = s.confirm(&code, NOW).unwrap();
    a.register_with_relay(&t, "https://relay.example", "setup")
        .unwrap();
    a.sync(&t, NOW + 1).unwrap();
    (a, t)
}

fn backoff(r: Result<impl Sized, AccountError>) -> core_sync::backoff::Backoff {
    match r {
        Err(AccountError::Sync(SyncError::Backoff(b))) => b,
        Err(e) => panic!("expected a backoff, got {e}"),
        Ok(_) => panic!("expected a backoff, got success"),
    }
}

#[test]
fn offline_edits_sync_after_reconnect_and_attempts_are_paced() {
    let (mut a, t) = setup();
    t.mode.set(Mode::Down);
    let id = a.save_login(None, &login("Bank"), NOW + 10).unwrap();

    assert!(matches!(
        a.sync(&t, NOW + 11),
        Err(AccountError::Sync(SyncError::Transport(_)))
    ));
    let st = a.sync_status(NOW + 12).unwrap();
    assert_eq!(st.pending, 1, "the edit stays queued");
    assert!(st.backoff.is_some_and(|b| !b.quota));

    // while paused nothing is sent
    let sent = *t.sent.borrow();
    let b = backoff(a.sync(&t, NOW + 1_000));
    assert_eq!(*t.sent.borrow(), sent);

    // a second failure waits longer than the first
    let first_wait = b.retry_at_ms - (NOW + 11);
    assert!(a.sync(&t, b.retry_at_ms).is_err());
    let b2 = a.sync_status(b.retry_at_ms + 1).unwrap().backoff.unwrap();
    assert!(b2.retry_at_ms - b.retry_at_ms > first_wait);

    // network back, pause over: the queued edit arrives and the pause is gone
    t.mode.set(Mode::Up);
    a.sync(&t, b2.retry_at_ms).unwrap();
    let st = a.sync_status(b2.retry_at_ms + 1).unwrap();
    assert_eq!((st.pending, st.backoff), (0, None));
    assert_eq!(a.get_login(&id).unwrap().title, "Bank");
    assert_eq!(t.relay.record_count(), 1);
}

#[test]
fn quota_errors_back_off_and_say_so() {
    let (mut a, t) = setup();
    a.save_login(None, &login("Mail"), NOW + 10).unwrap();
    t.mode.set(Mode::Quota);
    assert!(matches!(
        a.sync(&t, NOW + 11),
        Err(AccountError::Sync(SyncError::Status(429)))
    ));
    let b = backoff(a.sync(&t, NOW + 12));
    assert!(b.quota, "status must say the relay is throttling");
    assert!(b.retry_at_ms >= NOW + 11 + 60_000);
    assert!(
        AccountError::Sync(SyncError::Backoff(b))
            .to_string()
            .contains("limiting")
    );

    // "sync now" overrides the pause; success clears it
    t.mode.set(Mode::Up);
    a.sync_now(&t, NOW + 13).unwrap();
    assert_eq!(a.sync_status(NOW + 14).unwrap().backoff, None);
    assert_eq!(a.sync_status(NOW + 14).unwrap().pending, 0);
}
