# NEXORA SafeVault encrypted backups v1 — Phase 4.1

New download names start with `nexora-safevault-backup-`. Older VELNAR-named
archives remain supported. The authenticated v1 format identifiers below retain
their original bytes; renaming a file does not change its contents or identity.

Status: implemented and tested; independent security audit is pending. Use
synthetic test data in this development build.

## User flow

Use **Offline Backup** to open a downloaded archive with its backup password
and read the export snapshot. After the production app has cached its public
files, the viewer works after an offline reload. The viewer locks when the tab
is hidden, when the page closes or after five minutes without interaction.
Use **Backups → Restore into this vault** to add the archived entries to a live
vault.

If you have lost your master password and have a backup, sign in to your
account and use **Create another vault** on the unlock screen. Open **Backups**
in the new vault and restore with the backup password. The original vault
remains available from the vault selector.

Sign in and unlock a destination vault, then open **Backups**.

For export, enter and confirm a **separate backup password** of 12–1,024
characters. Prepare Encrypted Backup refreshes/authenticates all current entries
and creates a new encrypted snapshot. Download saves a JSON archive; its filename
contains only a timestamp. Prepare again to include later changes. The password
is not included in the file or sent to Django. Keep both the file and its password.

For restore, select a file and enter **that file's backup password**, not the
destination master password. Validate and Preview decrypts/authenticates locally,
shows the snapshot date, entry count and first ten titles, and checks a scoped
commit receipt. It does not insert entries. Restore requires a separate explicit
click. Titles are escaped text; passwords are never shown in the preview.

Restore adds fresh copies to the currently unlocked vault. It does not edit or
delete existing entries, reuse source entry IDs/nonces, or change the destination
master password. Categories, favorites, Unicode, password whitespace and optional
empty website/notes fields are preserved. New records start at revision 1 with new
server timestamps; original IDs/revisions/timestamps remain only inside the archive.

New exports include active entries only; Trash is excluded. Restore a Trash
item before preparing a backup to include it. Earlier archives may retain copies
of entries later trashed or permanently deleted. See [Trash semantics](trash.md).

The archive is an entry snapshot. Account credentials, sessions and account/security
settings are not backed up. Knowing the backup password can recover the snapshot
into another accessible vault, but does not reveal/reset the original vault master
password or recover changes made after export. Forgetting the backup password makes
this file unrecoverable; there is no server-side reset for it.

## File format and authentication

All binary encodings, UTF-8 handling, KDF parameters and wrapped-key rules reuse
`encryption-format.md`. Each export creates an independent random 32-byte data key,
fresh Argon2id salt and wrapping nonce. The archive never encrypts under the live
vault data key, avoiding nonce reuse across archive and entry encryption domains.
Argon2id remains 64 MiB, three passes, four lanes, v1.3, with 32 output bytes.
Derivation runs in the existing terminable Worker with no weaker fallback.

The top-level JSON has exactly these fields, in canonical writer order:

```text
format: "velnar.safevault.backup"
version: 1
encryption: {the v1 crypto profile, id, kdf_salt, wrap_nonce, wrapped_key}
nonce: Base64(12 fresh random bytes)
ciphertext: Base64(AES-256-GCM encrypted content || 16-byte tag)
```

`encryption.id` is a fresh archive UUID, independent of the source vault UUID.
`encryption` fields use this order: format_version, cipher, kdf, kdf_version,
kdf_memory_kib, kdf_iterations, kdf_parallelism, id, kdf_salt, wrap_nonce, wrapped_key.
Wrapped-key AAD is the existing v1 wrap string using this archive UUID/salt.
Content AAD is exactly this UTF-8 string, with no trailing newline:

```text
velnar.safevault:1:backup:{encryption.id}
```

The **entire content** is one authenticated ciphertext, including date and record
membership, so truncating/removing/reordering records cannot yield a valid partial
backup. Decrypted content has exactly version=1, exported_at (ISO timestamp),
source_vault_id (UUID), and entries (array). Each entry contains original_id,
original_revision, created_at, updated_at and payload. It contains the complete
record, including any [encrypted attachments](attachments.md), using the same
payload schema as a live entry. Source identities and timestamps are not exposed
in the header.

The importer validates header/profile/encoding/size before key derivation, verifies
the whole AES-GCM tag, validates all record schemas, rejects duplicate source IDs,
and publishes no partial plaintext on failure. Unsupported versions and unknown
fields are rejected. Empty vault exports are valid; an empty backup needs no write.

Archive limits are 48 MiB for a file, 32 MiB for decrypted content, 5,000 records and
64 KiB of text per entry, plus its bounded attachments. File size is checked before browser file reads and again
by the standalone parser. Formats are not compressed, avoiding decompression bombs.

## Server commit and retry safety

The file and backup password are never uploaded. After preview and confirmation,
the client encrypts each payload under the destination's current nonextractable
key with a fresh UUID/nonce and entry AAD/revision 1. Only these encrypted envelopes
are sent to the authenticated, CSRF-protected, no-store endpoint:

```text
POST /api/vaults/<destination>/restores/
{backup_id, archive_digest, entries: [{id, nonce, ciphertext}]}

GET /api/vaults/<destination>/restores/<backup_id>/
```

`backup_id` is the archive UUID. `archive_digest` is SHA-256 of the normalized known
outer JSON fields in the order above, encoded as UTF-8. This is an idempotency
fingerprint, **not a password verifier or cryptographic substitute for the GCM tag**.
Normalization makes whitespace/key reordering irrelevant to repeated imports.
The keyless server cannot verify that digest against a file it never receives;
correct clients authenticate/validate the archive locally.

The service locks the destination vault and atomically validates capacity,
conflicting IDs and all current/historical nonce reservations, inserts new nonce
reservations and entries, and creates a RestoreReceipt. Any failure rolls back
all three. No update/delete operation is performed on existing entries. The
additive migration creates only this receipt table. Receipts contain vault ID,
archive UUID/digest, committed count and timestamp, not decrypted fields.

The receipt's unique (destination vault, backup_id) prevents repeated or concurrent
imports of the same archive. A matching digest/count returns the existing receipt
without inserting duplicates, even if a retry generated fresh encrypted envelopes.
A conflicting digest/count returns HTTP 409. Receipt reads/writes are scoped to
ownership; other accounts cannot discover/reuse a destination's receipt.

After an uncertain connection outcome, unlock/reselect the same file and validate
again: the receipt determines whether it already committed. The client does not
automatically replay writes. In v1 the same archive can be restored **only once per
destination vault**, even if some imported entries are later deleted. To deliberately
create another copy, use a different destination vault or a newly exported archive.
Do not purge receipts while a vault is live; they are not authentication counters.

The restore body limit is 36 MiB and its request budget is six per hour per peer IP,
checked after authentication/ownership and before parsing the body. Key rotation
uses the same body limit; entry creates and edits use a smaller limit that allows
one attachment envelope. Other endpoints keep their 128 KiB bound. The custom BaseParser delegates JSON decoding to DRF while
bounding the stream directly; it avoids the installed DRF's eager raw-body buffering
for JSONParser subclasses. Concurrent vault writes share the vault lock. Ordinary
create/edit and restores enforce the same 5,000-entry/32 MiB encoded-ciphertext vault
capacity so a restore cannot produce a vault that this client cannot reopen.

## Local lifetime and validation

Preview plaintext/draft state is held in memory and discarded on lock, account
change, pagehide or leaving Backups. Pending Worker/network responses are invalidated
by epochs; file-read generations reject late file reads. Download URLs are revoked
on replacement/unmount. The downloaded encrypted file remains until the user deletes
it. Browser strings, swap, OS clipboard and internals cannot be reliably zeroized;
this is not a claim of forensic memory erasure. Trusted client code/origin remains
part of the threat model.

Tests cover export/restore preservation, whole-file tampering/truncation, wrong
passwords, unsupported/hostile KDF profiles, empty archives, canonical fingerprints,
preview without writes, late results/lock/cancel, fresh destination identities,
atomic rollback, ownership/CSRF, idempotent and concurrent retries, capacities and
request/parser limits. Browser QA uses a separate disposable database with public
synthetic fixtures: downloaded archive, file chooser, preview before any insert,
explicit restore, duplicate detection and wrong-password rejection. Python independently
decrypts the browser archive and both original/restored records to verify exact data
and distinct nonces. No real vault data is used for test records.

Run the existing frontend tests/build/lint and Django tests as documented in README.
Automated backups, legacy migration, and an independent
security audit remain outside the backup workflow.
