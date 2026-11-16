//! Local store: one SQLite table of encrypted record blobs plus the public sync columns
//! (id, vault, hlc, tombstone), exactly what the relay sees (ADR 0001, SR-15). Nothing
//! decrypted is ever written; search runs over an [`Index`] that lives in memory only.

mod index;

pub use index::Index;
use rusqlite::{Connection, OptionalExtension, params};
use std::path::Path;

/// Schema migrations, applied in order; `PRAGMA user_version` is the count applied.
/// Append only: never edit or reorder a shipped entry.
const MIGRATIONS: &[&str] = &[
    "CREATE TABLE records (
        id    TEXT PRIMARY KEY,
        vault TEXT NOT NULL,
        hlc   TEXT NOT NULL,
        tomb  INTEGER NOT NULL CHECK (tomb IN (0, 1)),
        blob  BLOB NOT NULL
    ) STRICT",
    "CREATE INDEX records_by_vault ON records (vault, hlc)",
    // Local edits not yet acknowledged by the relay; `base` is the hlc the relay last had.
    "CREATE TABLE pending (id TEXT PRIMARY KEY, base TEXT) STRICT",
    // Small key/value state (sync cursor, clock, account header); nothing secret in plaintext.
    "CREATE TABLE meta (k TEXT PRIMARY KEY, v BLOB NOT NULL) STRICT",
];

#[derive(Debug)]
pub enum StoreError {
    Sqlite(rusqlite::Error),
    /// The database was written by a newer build; refuse rather than corrupt it.
    SchemaTooNew(usize),
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sqlite(e)
    }
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Sqlite(e) => write!(f, "store error: {e}"),
            Self::SchemaTooNew(v) => write!(f, "database schema {v} is newer than this build"),
        }
    }
}

impl core::error::Error for StoreError {}

/// A sync record as stored: public metadata plus the sealed envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Record {
    pub id: String,
    pub vault: String,
    /// 24 lowercase hex chars; string order equals HLC order.
    pub hlc: String,
    pub tombstone: bool,
    pub blob: Vec<u8>,
}

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::init(Connection::open(path)?)
    }

    pub fn open_in_memory() -> Result<Self, StoreError> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(mut conn: Connection) -> Result<Self, StoreError> {
        let applied = user_version(&conn)?;
        if applied > MIGRATIONS.len() {
            return Err(StoreError::SchemaTooNew(applied));
        }
        for (i, sql) in MIGRATIONS.iter().enumerate().skip(applied) {
            let tx = conn.transaction()?;
            tx.execute_batch(sql)?;
            tx.execute_batch(&format!("PRAGMA user_version = {}", i + 1))?;
            tx.commit()?;
        }
        Ok(Self { conn })
    }

    /// Insert or replace by id, but only if `rec.hlc` is newer than what is stored (the same
    /// last-writer-wins rule the relay applies). Returns whether the record was written.
    pub fn put(&self, rec: &Record) -> Result<bool, StoreError> {
        let n = self.conn.execute(
            "INSERT INTO records (id, vault, hlc, tomb, blob) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET vault = ?2, hlc = ?3, tomb = ?4, blob = ?5
             WHERE excluded.hlc > records.hlc",
            params![rec.id, rec.vault, rec.hlc, rec.tombstone, rec.blob],
        )?;
        Ok(n > 0)
    }

    pub fn get(&self, id: &str) -> Result<Option<Record>, StoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT id, vault, hlc, tomb, blob FROM records WHERE id = ?1",
                [id],
                row,
            )
            .optional()?)
    }

    /// A local edit: store the record (it must carry a newer hlc than the stored one) and
    /// queue it for push. The queue remembers the hlc the relay last had, taken from the
    /// first unpushed edit, so several edits before a sync still push as one update.
    pub fn put_local(&self, rec: &Record) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let base: Option<String> = tx
            .query_row("SELECT hlc FROM records WHERE id = ?1", [&rec.id], |r| {
                r.get(0)
            })
            .optional()?;
        let written = self.put(rec)?;
        if written {
            tx.execute(
                "INSERT OR IGNORE INTO pending (id, base) VALUES (?1, ?2)",
                params![rec.id, base],
            )?;
        }
        tx.commit()?;
        Ok(written)
    }

    /// A record from the relay. Applied only if newer; a newer remote copy supersedes (and
    /// drops) an unpushed local edit of the same record (merging is #40).
    pub fn put_remote(&self, rec: &Record) -> Result<bool, StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        let written = self.put(rec)?;
        if written {
            tx.execute("DELETE FROM pending WHERE id = ?1", [&rec.id])?;
        }
        tx.commit()?;
        Ok(written)
    }

    /// Whether `id` has a local edit the relay has not acknowledged yet.
    pub fn is_pending(&self, id: &str) -> Result<bool, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT 1 FROM pending WHERE id = ?1", [id], |_| Ok(()))
            .optional()?
            .is_some())
    }

    /// Adopt a remote record over an unpushed local edit that the merge found redundant,
    /// even if its hlc is older: the local edit adds nothing, so it is dropped.
    pub fn replace(&self, rec: &Record) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO records (id, vault, hlc, tomb, blob) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET vault = ?2, hlc = ?3, tomb = ?4, blob = ?5",
            params![rec.id, rec.vault, rec.hlc, rec.tombstone, rec.blob],
        )?;
        tx.execute("DELETE FROM pending WHERE id = ?1", [&rec.id])?;
        tx.commit()?;
        Ok(())
    }

    /// Store the result of merging a local edit with the relay copy `base`, and queue it to be
    /// pushed on top of that copy. `rec.hlc` must be newer than `base`.
    pub fn put_merged(&self, rec: &Record, base: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO records (id, vault, hlc, tomb, blob) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET vault = ?2, hlc = ?3, tomb = ?4, blob = ?5",
            params![rec.id, rec.vault, rec.hlc, rec.tombstone, rec.blob],
        )?;
        tx.execute(
            "INSERT INTO pending (id, base) VALUES (?1, ?2)
             ON CONFLICT(id) DO UPDATE SET base = ?2",
            params![rec.id, base],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Queue every stored record for push, as against an empty relay (base = nothing). This is how
    /// a relay is rebuilt from a device's full local copy (SR-9); records already queued keep
    /// their base.
    pub fn queue_all(&self) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO pending (id, base) SELECT id, NULL FROM records",
            [],
        )?;
        Ok(())
    }

    /// Unpushed local edits with the hlc the relay is expected to hold, oldest first.
    pub fn pending(&self) -> Result<Vec<(Record, Option<String>)>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT r.id, r.vault, r.hlc, r.tomb, r.blob, p.base
             FROM pending p JOIN records r ON r.id = p.id ORDER BY r.hlc, r.id",
        )?;
        Ok(stmt
            .query_map([], |r| Ok((row(r)?, r.get(5)?)))?
            .collect::<Result<_, _>>()?)
    }

    /// The relay accepted `hlc` for `id`: forget the queue entry unless the record was
    /// edited again meanwhile (then the accepted hlc becomes the new base).
    pub fn ack(&self, id: &str, hlc: &str) -> Result<(), StoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM pending WHERE id = ?1 AND EXISTS (SELECT 1 FROM records WHERE id = ?1 AND hlc = ?2)",
            params![id, hlc],
        )?;
        tx.execute(
            "UPDATE pending SET base = ?2 WHERE id = ?1",
            params![id, hlc],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The relay holds `base` for this pending record (`None` = it holds nothing, e.g. after a
    /// rebuild): push against that.
    pub fn rebase(&self, id: &str, base: Option<&str>) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE pending SET base = ?2 WHERE id = ?1",
            params![id, base],
        )?;
        Ok(())
    }

    pub fn meta_get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .conn
            .query_row("SELECT v FROM meta WHERE k = ?1", [key], |r| r.get(0))
            .optional()?)
    }

    pub fn meta_set(&self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO meta (k, v) VALUES (?1, ?2) ON CONFLICT(k) DO UPDATE SET v = ?2",
            params![key, value],
        )?;
        Ok(())
    }

    /// All records of a vault in HLC order, tombstones included.
    pub fn list(&self, vault: &str) -> Result<Vec<Record>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, vault, hlc, tomb, blob FROM records WHERE vault = ?1 ORDER BY hlc, id",
        )?;
        Ok(stmt.query_map([vault], row)?.collect::<Result<_, _>>()?)
    }
}

fn user_version(conn: &Connection) -> rusqlite::Result<usize> {
    let v: u32 = conn.query_row("PRAGMA user_version", [], |r| r.get(0))?;
    Ok(usize::try_from(v).unwrap_or(usize::MAX))
}

fn row(r: &rusqlite::Row) -> rusqlite::Result<Record> {
    Ok(Record {
        id: r.get(0)?,
        vault: r.get(1)?,
        hlc: r.get(2)?,
        tombstone: r.get(3)?,
        blob: r.get(4)?,
    })
}

#[cfg(test)]
mod tests;
