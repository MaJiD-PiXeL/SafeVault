# Encrypted Trash

Open an entry, choose **Move to Trash** and confirm. The saved encrypted entry
disappears from All Passwords, Favorites, the main search, health counts and new
backups. Unsaved edits are discarded. Open **Trash** in the sidebar or mobile
navigation to search deleted entries, restore them, or start a separate
**Delete forever** confirmation. Cancel deletion makes no request.

Trash has no automatic expiry or background purge. Restore keeps the original
UUID, fields, category, favorite status and creation time. Restored entries can
be edited normally. Both active entries and Trash count toward the existing
5,000-entry / 32 MiB encoded-ciphertext limit. Restore allocates no new entry;
permanent deletion frees the entry's storage.

All entry fields stay encrypted under the same vault key. Unlock authenticates
and decrypts active and trashed entries before publishing either set. A corrupt
record fails the whole load. The controller clears both sets on lock/account
change; the Trash view discards its search and confirmation state on unmount.
No persistent browser storage is introduced.

## Migration, encryption and concurrency

Migration `0003_vaultentry_deleted_at_vaultentry_state_version_and_more` adds
`deleted_at` (nullable indexed timestamp), `state_version` (initially 1), and a
bounded positive-counter constraint. Existing rows start active, retaining their
encrypted bytes, wrapping keys, ciphertext revisions and timestamps. Entries
permanently deleted before this feature require an earlier backup to recover.

`revision` remains the encrypted-content revision used in AES-GCM AAD. Move and
restore leave it, the nonce and ciphertext unchanged. `state_version` increments
on each move/restore, preventing an old editor or confirmation from becoming
valid after a move-and-restore cycle. Edits require active state; restore/purge
require Trash state. Each checks both counters. Counter overflow is rejected.

Lifecycle timestamps/counters are server-visible metadata outside GCM AAD. These
checks prevent accidental/concurrent stale writes; they do not implement
malicious-server rollback detection or offline sync. No plaintext entry fields
or new cryptographic formats are introduced.

All mutation services lock the owning vault before the entry in transactions.
Creates and backup restores use the same vault lock, serializing storage budgets
and competing lifecycle operations. Session ownership, CSRF and no-store remain
mandatory. Stale/wrong-state writes return 409 and are never replayed. After an
uncertain network outcome, unlock/refresh before retrying.

## API and deployment

| Method | Path under `/api/vaults/<vault>/` | Behavior |
| --- | --- | --- |
| GET | `entries/` | Paginated active entries |
| GET | `entries/?state=trash` | Paginated Trash |
| GET | `entries/?state=all&page=1` | Combined bounded load used by the web client |
| GET | `entries/<entry>/` | Owned envelope, including lifecycle metadata |
| PATCH | `entries/<entry>/` | Edit an active encrypted entry |
| DELETE | `entries/<entry>/` | Move to Trash, returning the envelope (200) |
| POST | `entries/<entry>/restore/` | Restore and return the envelope (200) |
| DELETE | `entries/<entry>/purge/` | Permanently delete from Trash (204) |

Every edit/move/restore/purge requires `expected_revision` and
`expected_state_version`. Edits additionally require fresh `nonce`/`ciphertext`.
Lifecycle actions send only the counters. Submitted `deleted_at`/`state_version`
are rejected; returned envelopes include these server-controlled fields.

Deploy the backend, migration and frontend together, then reload old clients.
Older clients missing the state counter receive 400 on mutations; the new client
rejects envelopes missing lifecycle metadata. Encryption v1 and backup v1 remain
byte-compatible. Apply the additive migration with:

```powershell
backend/.venv/Scripts/python.exe -B backend/manage.py migrate
```

## Permanent deletion and backups

Permanent deletion requires a separate confirmation bound to the reviewed
version. It removes the live encrypted row; nonce reservations and backup
restore receipts survive. It does not erase downloaded backups, database
snapshots, WAL, storage-provider history, or browser/OS memory. This is not
forensic erasure.

New backups include active entries only. Restore a Trash item before preparing
a backup if it should be included. Earlier archives may still contain a deleted
entry. A file already restored into a destination remains idempotent after its
imported entries are trashed/purged; receipts are not cleared.

## Validation

Backend tests cover exact ciphertext preservation, stale counters across cycles,
ownership/CSRF, strict fields, mixed-state pagination, capacity, overflow,
retained nonces/receipts, and PostgreSQL restore-versus-purge concurrency.
Frontend tests cover account/vault transport composition, response validation,
data preservation, backup exclusion, stale editors, late writes and lock/account
cleanup. Migration and browser QA use isolated databases with synthetic data.

The migration regression test upgrades a populated pre-Trash schema and verifies
that entry ciphertext, nonces, content revisions, timestamps, wrapped keys, nonce
reservations and restore receipts survive unchanged. Existing entries become
active with state version 1. The test restores the latest schema during cleanup.

Validation on 2026-11-03:

- All 87 backend tests passed on a fresh temporary PostgreSQL database, including
  the migration regression and restore-versus-purge concurrency test.
- All 66 frontend tests, production build and lint passed. Django checks and
  `makemigrations --check --dry-run` passed with no model changes pending.
- The 29 CLI tests completed with the opt-in MySQL test skipped.
- Browser QA used the production frontend build and a separate SQLite database
  seeded with the public encryption fixture. Real Worker/Web Crypto unlock,
  Move to Trash, discarding unsaved edits, removal from active/favorite/health
  counts, permanent-delete warning/cancellation, and restoration of the original
  title/category/favorite succeeded. A read-only database check confirmed the
  original encrypted bytes and content revision survived the browser round trip;
  the state version became 3. Reload returned to the locked screen.
  Permanent deletion itself is covered by
  the API/controller tests; browser QA cancelled its confirmation.

No migration or test data was applied to the developer's vault database.
