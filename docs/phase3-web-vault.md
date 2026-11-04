# Phase 3 — client encryption and the web vault

The existing dashboard displays live entries after account sign-in and vault
unlock. Guest users retain the original sample preview. New modules extend the
existing app; the CLI, legacy databases and branding remain intact.

## Using this build

Start Django and Vite as described in the root README. Sign in under Account,
then open All Passwords. Create a master passphrase of at least 12 characters,
different from the account password, or unlock an existing vault. Account sign-in
does not unlock a vault; account recovery cannot recover the vault's key.

Add New Item opens the encrypted-entry form. The row's Edit button supports
reveal, edit and deletion. Website and notes are optional. Favorite status and
category are encrypted alongside all other entry fields. Search includes title,
username, website, category and notes and runs locally after decryption; search
terms never go to Django. Favorites and the category dropdown also filter
locally. Refresh Entries fetches and authenticates a fresh encrypted snapshot.

The generator uses Web Crypto random bytes with rejection sampling and a random
shuffle, never Math.random. Its 12–128 character passwords contain upper/lowercase
letters, numbers and symbols and never go to the server. Copy is an explicit
browser action; clipboard contents are outside the vault's control and are not
cleared automatically.

## Cryptography

Storage v1 is unchanged (`encryption-format.md`). `hash-wasm` 4.12.0 is pinned
in package.json and the lockfile. Argon2id v1.3 uses 64 MiB, three passes, four
lanes and 32 output bytes. Derivation runs in a fresh module Worker whose WASM
is bundled with the app, without a runtime CDN. Failure/timeout has no weaker
fallback. The Worker terminates after completion, error, timeout or cancellation.

The passphrase is UTF-8 encoded without trimming/normalization; unpaired Unicode
surrogates are rejected rather than silently replaced. Its bytes cross
only the local Worker messaging boundary; no account/vault API payload includes
it. The derived wrapping key authenticates and decrypts a random vault data key.
Wrapping/data keys are nonextractable AES-256-GCM Web Crypto keys. Salt and
nonces use the browser CSPRNG and all tags are 128 bits. Wrap/entry UUID/revision
AAD follows the v1 contract exactly.

Validation rejects unsupported crypto profiles, noncanonical Base64, invalid
sizes, mismatched vault identifiers/revisions and unsupported payload schemas.
Every record must authenticate and validate before any entries reach the UI;
a damaged record fails the entire unlock without exposing a partial snapshot.

The public fixture `frontend/tests/fixtures/encryption-v1.json` was generated
with Python cryptography Argon2id/AESGCM. Its passphrase, raw keys and payload are
synthetic test vectors, not real credentials, and are not imported by production
code. Tests check exact derived bytes, UTF-8/whitespace, AAD, authentication tags,
interoperability, wrong passwords/keys, tampering, nonextractability and fresh
random envelopes. Fresh client ciphertext also decrypts with Node AES-GCM.

## Memory and locking

The controller owns the live key and decrypted entries. Public snapshots never
contain a key or master password. Lock drops key/plaintext references, aborts
requests and terminates derivation. Epoch checks prevent late unlock/save
responses from restoring plaintext after lock/account change. Editors, reveal
controls, search and category state are discarded. Reload starts locked. Keys
and plaintext are not persisted to localStorage, sessionStorage, IndexedDB, URLs,
logs or telemetry.

Byte buffers are overwritten where practical. JavaScript strings, browser
internals, garbage collection, swap and clipboard contents cannot be reliably
zeroized by this app. Dropping references is not forensic memory erasure.
Unlocked browsers and compromised clients/XSS can expose secrets. The delivered
client code/origin must be trusted: at-rest zero-knowledge storage alone does
not protect against a malicious replacement client from a compromised origin.

Security Center stores inactivity limits from 60 to 3,600 seconds and hidden-tab
locking; defaults are five minutes and hidden-tab locking on. Idle expiry is
checked before accepting renewed activity, including after sleep. Pagehide and
explicit lock always lock. Sign-out locks locally before the logout request.
Account changes, unavailable account state and auth failures also close the
vault. Session expiry/revocation is detected on the next failed request or the
existing focus/one-minute account check.

## API and concurrency

All vault APIs require a Django session, writes enforce CSRF and responses are
no-store. Ownership comes only from authenticated server context.

| Method | Path | Accepted write data |
| --- | --- | --- |
| GET/POST | `/api/vaults/` | v1 metadata, UUID and wrapped key |
| GET/POST | `/api/vaults/<uuid>/entries/` | UUID, nonce, ciphertext |
| GET | `/api/vaults/<uuid>/entries/<uuid>/` | none |
| PATCH | `/api/vaults/<uuid>/entries/<uuid>/` | nonce, ciphertext, expected_revision, expected_state_version |
| DELETE | `/api/vaults/<uuid>/entries/<uuid>/` | expected_revision, expected_state_version (move to Trash) |
| POST | `/api/vaults/<uuid>/entries/<uuid>/restore/` | expected_revision, expected_state_version |
| DELETE | `/api/vaults/<uuid>/entries/<uuid>/purge/` | expected_revision, expected_state_version |
| GET/PATCH | `/api/security-settings/` | auto_lock_seconds, lock_on_hidden |

Both vault and entry identities are scoped to the owner. Unknown/plaintext
fields, owner overrides and noncanonical UUIDs are rejected. The keyless server
validates encoding/size, but cannot verify GCM tags or prove that valid Base64
was encrypted; only correct clients can do that.

Writes use the existing transaction/row-lock services. Stale revisions and reused
nonces return 409 conflicts. Nonce reservations survive edits/deletion. Editors
retain their original revision so a refresh cannot silently make an old draft
overwrite newer data. Writes are never automatically replayed. Unconfirmed
creation requires reloading metadata before another creation attempt.

The later Trash extension adds lifecycle metadata without changing encryption v1.
The client loads active and trashed envelopes together with `?state=all&page=1`,
then separates them after authentication/decryption. Default entry lists include
active items only. See [Trash](trash.md) for retention, version checks, permanent
deletion, capacity and backup semantics.

Entry pages contain 50 records. Clients construct local page paths rather than
following server URLs, check counts/duplicates and require a complete snapshot.
Opening is limited to 5,000 entries and 32 MiB of encoded ciphertext; exceeding
limits returns an explicit error without silently omitting entries. Each entry
allows 64 KiB plaintext plus the 16-byte tag. A bounded JSON parser limits even
streamed bodies to 128 KiB and rejects excessive nesting. Vault creation is
capped at ten per account under a row lock. The UI creates the first vault and
can select among multiple existing vaults.

## Validation and remaining work

Automated coverage includes ownership/CSRF, encrypted CRUD, optional fields,
strict parsing, revisions/nonces, pagination, preferences, byte compatibility,
cancellation, late writes, auth loss, stale editors and idle/hidden locking.
PostgreSQL concurrency tests cover storage and authentication request budgets.

The real-browser smoke test uses a separate local backend/frontend and a new
disposable SQLite database with synthetic credentials. It exercises the actual
Worker/Web Crypto path, creates/edits an entry, searches, filters Favorites,
locks/unlocks, rejects a wrong master and confirms reload starts locked.
Python independently decrypts the browser-produced record and verifies password
whitespace, revision, edited title and optional empty fields, and confirms the
test database contains no plaintext master, account/entry password or title.
A real one-minute inactivity test also returns the page to its locked state.
The real safevault database is not used for these records.

Master-password rewrapping is now available in Security Center; see
[the change protocol and its limits](master-password.md). Each unlock fetches
current vault metadata, and successful password changes lock the client.

Independent audit, recovery/data-key rotation, rollback detection, offline
storage, conflict-aware device sync, large-vault streaming, attachments/secure
notes/card schemas and production hardening remain future work. No legacy data
migration or scheduled cleanup/sync is introduced. Use synthetic test entries.

References: [hash-wasm API](https://github.com/Daninet/hash-wasm),
[RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html),
[AES-GCM parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesGcmParams).
