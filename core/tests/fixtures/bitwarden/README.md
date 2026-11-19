# Bitwarden import fixtures

Synthetic only: no real data. Authored from Bitwarden's open export models (spike #12), not exported from a real account, so confirm against a real throwaway-account export when building #67-#69.

- `unencrypted.json`: individual-vault JSON export. One of every item type (1-8), an unknown type (99), all five URI match values plus null, field types 0-3, password history, FIDO2 credential, trashed+archived item, Unicode/CRLF values.
- `org-collections.json`: organization-style export with `collections` and `collectionIds`.
- `unencrypted.csv`: CSV export (login and note only; shows what CSV cannot carry).
- `password-protected.json`: the `unencrypted.json` content under a password-protected export, PBKDF2-SHA256 600000 iterations, password `synthetic-export-password`. Built from the algorithm in Bitwarden's source (PBKDF2, HKDF-Expand `enc`/`mac`, AES-256-CBC + HMAC-SHA256 EncString type 2); round-trips with an independent decrypt but has not been opened by Bitwarden itself.

`core-import/tests/fixtures_are_synthetic.rs` scans every file under `tests/fixtures/`: all URL hosts and email domains must be RFC 2606 reserved, and no token or private-key signature may appear. Goldens (`golden/`) are compared in CI; regenerate with `UPDATE_GOLDEN=1 cargo test -p core-import` and review the diff. The encrypted fixture needs no golden: its import must equal the plaintext import (#68). The CSV fixture's golden is `golden/unencrypted-csv.import.json` (#69). Types 3-8 import as secure notes; only the unknown type 99 is skipped. `password-protected.json` must be re-sealed whenever `unencrypted.json` changes (its import must equal the plaintext import).
