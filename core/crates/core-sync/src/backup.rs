//! Optional encrypted backups on the relay's R2 bucket (#47). Transport only: the file is the one
//! `seal-core` writes (sealed under the Account Key), sent as base64 text and stored as received,
//! so the relay can neither read nor alter it undetected. Only the newest few are kept.

use crate::client::call;
use crate::{Device, SyncError, Transport, b64, unb64};
use serde::Deserialize;

/// A backup the relay holds.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteBackup {
    /// Opaque name, pass it to [`download`]. Sorts by upload time.
    pub key: String,
    /// Stored size (base64 characters).
    pub size: u64,
    /// Unix ms the relay received it.
    pub uploaded: u64,
}

/// Upload a backup file. The relay answers 501 when the owner did not enable R2 backups, and 413
/// above its size cap (about 3 MiB of file).
pub fn upload(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
    file: &[u8],
) -> Result<String, SyncError> {
    let res = t.send(&me.sign_request("PUT", "/v1/backup", b64(file).into_bytes(), now_ms))?;
    if res.status != 201 {
        return Err(SyncError::Status(res.status));
    }
    #[derive(Deserialize)]
    struct Resp {
        key: String,
    }
    serde_json::from_slice::<Resp>(&res.body)
        .map(|r| r.key)
        .map_err(|_| SyncError::Protocol("backup upload"))
}

/// The backups held, newest first.
pub fn list(t: &dyn Transport, me: &Device, now_ms: u64) -> Result<Vec<RemoteBackup>, SyncError> {
    #[derive(Deserialize)]
    struct Resp {
        backups: Vec<RemoteBackup>,
    }
    let body = call(t, me, now_ms, "GET", "/v1/backup", Vec::new())?;
    serde_json::from_slice::<Resp>(&body)
        .map(|r| r.backups)
        .map_err(|_| SyncError::Protocol("backup list"))
}

/// One backup file, ready for `Account::restore` / `verify_backup` (which authenticate it).
pub fn download(
    t: &dyn Transport,
    me: &Device,
    now_ms: u64,
    key: &str,
) -> Result<Vec<u8>, SyncError> {
    let body = call(
        t,
        me,
        now_ms,
        "GET",
        &format!("/v1/backup/{key}"),
        Vec::new(),
    )?;
    decode(&body).ok_or(SyncError::Protocol("backup body"))
}

/// Turn the stored text back into the file. Also for an object fetched by hand from the owner's
/// own bucket (dashboard or `wrangler r2 object get`) when no enrolled device is left to ask.
pub fn decode(stored: &[u8]) -> Option<Vec<u8>> {
    unb64(std::str::from_utf8(stored).ok()?.trim())
}
