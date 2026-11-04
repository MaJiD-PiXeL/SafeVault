# Changing the vault master password

Sign in, unlock the selected vault, then open **Security Center → Change master
password**. Enter the current master password, a different new passphrase of
12–1,024 characters, and its confirmation. Passwords are not trimmed or normalized.
The form clears submitted password fields, and unmounts on lock, account/vault
change or navigation. The vault locks on success; unlock with the new password.

The account password is separate and is not changed. Neither master password
nor any raw encryption key is sent to Django or persisted in browser storage.

## Encryption and data preservation

The client derives the current Argon2id wrapping key in its Worker and
authenticates/decrypts the current wrapped data key. It generates a fresh 16-byte
salt and 12-byte nonce, derives the new wrapping key with the unchanged v1
profile, and encrypts the same 32-byte data key using the existing wrap AAD.
The live key stays nonextractable. Temporary raw-key and derived-key byte
buffers are overwritten in success, failure and cancellation paths; JavaScript
strings and browser memory cannot be reliably zeroized.

Before submitting, the client authenticates all active and trashed entries with
the preserved data key. Wrong current passwords or damaged records submit no
wrapper update. No entry ciphertext, nonce, UUID, content revision, lifecycle
version, category or favorite status changes. Nonce reservations and backup
restore receipts survive. Backups keep their independent passwords and format.

## API and concurrency

`POST /api/vaults/<uuid>/master-password/` requires an authenticated owning
session and CSRF. Its only accepted fields are:

- `expected_kdf_salt`, `expected_wrap_nonce`, `expected_wrapped_key`: the exact
  current encrypted wrapper being replaced.
- `kdf_salt`, `wrap_nonce`, `wrapped_key`: fresh client-produced encoded bytes.

Canonical Base64 and exact byte lengths are mandatory. Unknown fields, plaintext
passwords, ownership overrides and crypto-profile changes are rejected. The
service locks the owning vault in a transaction, compares all three expected
fields and saves only the new wrapper plus the vault's update timestamp. Stale
requests return 409; concurrent changes from the same wrapper cannot both
commit. Reusing any current wrapper component is rejected. The expected tuple
is a compare-and-swap token; fresh random wrappers prevent accidental reuse,
but do not implement malicious-server rollback protection or a historical
wrapper-reuse registry. The keyless server cannot prove that submitted bytes
wrap the original data key or that a client checked the current password.

Successful responses return current v1 vault metadata with `Cache-Control:
no-store`. No database migration or encryption-format change is introduced.
Deploy the new backend endpoint and frontend together.

## Locking, interrupted requests and other devices

Each unlock fetches current vault metadata before deriving a key, so updated
clients do not unlock a cached old wrapper after another device changes the
password. Already unlocked devices retain the same data key and access.
This change does not revoke copied data keys, old wrapper snapshots, previous
backups, or old clients. Revoking compromised copies requires a separate data-key
rotation protocol, which is not implemented.

Once an update is dispatched, cached metadata is invalidated. Success locks the
client and retains the confirmed new wrapper. Conflicts, network failures,
malformed responses and cancellation after dispatch require loading the vault
list again. The client never automatically replays a password-change request.
After an uncertain outcome, load current metadata and try the new password;
if it fails, try the previous one. Lock/account changes invalidate late results,
and cannot republish keys, plaintext, metadata or a success message.

## Validation

Tests cover real Argon2id/AES-GCM rewrapping and independent Node AES-GCM
decryption of the preserved raw data key; wrong/old passwords, Unicode and
whitespace, cancellation and buffer cleanup; strict CSRF-authenticated
transport; active/Trash/receipt/nonce preservation; stale updates; and
PostgreSQL concurrency. Controller tests cover lock/account changes, fresh
metadata on unlock and uncertain responses.

An isolated localhost integration test exercises the real client crypto,
controller and Django API using the public synthetic encryption fixture. It
checks both successful changes and a deliberately lost response after the
server commits, recovery by reloading metadata, continued access to active and
trashed records, unchanged encrypted entry bytes, old-password rejection,
unchanged account login, and an earlier independent backup opening normally.
No developer vault or real credential is changed by these tests.

Validation on 2026-11-03: all 95 backend tests passed on a fresh temporary
PostgreSQL database; SQLite completed the same suite with its five concurrency
tests skipped. All 75 frontend tests, production build and lint passed. Django
checks and migration-drift checks passed. The localhost integration test passed,
and the production build opened its changed synthetic vault through the browser
Worker. The three-field Security Center form was visually inspected; password
changes themselves were exercised through automated crypto/controller/API tests.
