-- Database as shipped at schema version 1 (before the per-vault index). Used by the
-- forward-migration test; never edit, add v2.sql etc. when the schema moves on.
CREATE TABLE records (
    id    TEXT PRIMARY KEY,
    vault TEXT NOT NULL,
    hlc   TEXT NOT NULL,
    tomb  INTEGER NOT NULL CHECK (tomb IN (0, 1)),
    blob  BLOB NOT NULL
) STRICT;
INSERT INTO records VALUES ('rec-1', 'vault-1', '000000000001000000000001', 0, x'0102030405');
PRAGMA user_version = 1;
