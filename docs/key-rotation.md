# Rotating the vault encryption key

Unlock the vault and open **Security Center → Rotate vault encryption key**.
Enter the current master password and a different new passphrase of at least
12 characters. Keep the vault open while rotation runs. On success it locks;
use the new master password on this and other devices.

Rotation encrypts every saved record, including Trash, under a newly generated
256-bit key. Record IDs, content revisions, Trash status and timestamps are
preserved. Your account password and previously downloaded backup files are
independent and keep their existing passwords. Rotation disables any active
[vault recovery key](vault-recovery.md); set up a new one afterward. If a device or attacker already
copied plaintext, an old encrypted snapshot or an independent backup, rotation
cannot take back that copy. Rotate the individual credentials as well if they
may have been exposed.

If a concurrent change prevents rotation, reload the vault list and try again.
If the connection drops and the result cannot be confirmed, reload the vault
list and try the new master password first. If it fails, try the previous one.
The browser does not automatically repeat a rotation request.

## Protocol and deployment

The client reads a consistent snapshot of all encrypted entries, authenticates
the current wrapper with the supplied password, and generates a fresh data key,
Argon2id salt, and wrapping nonce. It decrypts and validates each record, then
encrypts its original bytes with fresh AES-GCM nonces and the same record AAD.
AES-GCM requires unique nonces for a given key; see [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final).
The browser sends only the new wrapper, encrypted envelopes and snapshot tokens.
Live keys are nonextractable, and the client clears temporary raw key and record
byte buffers. It cannot guarantee erasure of JavaScript strings or browser memory.

`POST /api/vaults/<uuid>/key-rotation/` requires an owning session and CSRF. It
accepts a bounded, rate-limited JSON batch. Under the same vault row lock used by
all entry writes, the service compares the old wrapper, key version and entry
snapshot version; requires exactly one replacement per current row; and checks
nonce uniqueness against both the batch and historical reservations. It commits
the wrapper, all replacement ciphertext, nonce reservations and both new
versions in one transaction. Restore receipts and entry metadata are preserved.
The keyless server cannot verify that a client used a new raw key, encrypted
equivalent plaintext or correctly checked the current master password.

Migration `vault.0005` initializes existing vaults at key version 1. The entry
list and sync endpoint report the current key version. Entry mutations, Trash
changes and backup restores compare `expected_key_version` inside the vault lock.
Omitting it is treated as version 1 for compatibility, so older clients cannot
write to a rotated vault. Current clients lock when they detect a key change
through sync or a rejected write, including when the vault is empty. A device
that is offline can reopen its last synced entries in the same tab with the
previous master password until it reconnects. Reconnecting invalidates that
copy when the key version has changed. [Offline editing guide](offline-edits.md)

Apply the migration and deploy the new frontend and backend together. Stop old
API workers before allowing rotation, and keep the key version checks in any
rollback build that will use the database after its first rotation. An older
backend does not enforce those checks. Rotation does not change the backup file
format or provide malicious-server rollback detection.

Tests exercise exact byte preservation with independent AES-GCM decryption,
ownership and CSRF, stale writes, snapshot and wrapper conflicts, transaction
rollback, PostgreSQL concurrency, and recovery after a lost response. A live
HTTP rehearsal with two separate sessions and a disposable database also
verified that Trash and an older independent backup remain readable. Use
synthetic entries until the independent security review is complete.
