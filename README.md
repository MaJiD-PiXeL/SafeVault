# NEXORA SafeVault

NEXORA's encrypted password workspace. **Beyond What Exists.**
Brand identity follows the existing NEXORA official website: its metallic N mark,
Manrope typography and obsidian/titanium/electric-blue palette. See
[branding and compatibility](docs/branding.md). The legacy CLI and encrypted
storage remain compatible with existing data.

The Python CLI manages encrypted passwords in MySQL. The React frontend is a
sample vault interface; the Django backend exposes metadata, liveness,
account authentication and session-management APIs.
Phase 1 adds encrypted-storage models and owner-scoped persistence services;
Phase 2 connects account sign-up/sign-in and session revocation to the frontend.
Phase 3 adds client Argon2id/AES-GCM, authenticated encrypted-vault CRUD, local
search/categories/favorites, the password generator and vault auto-lock.

## Setup

Install Python dependencies with `python -m pip install -r requirements.txt`.
Use the same Python environment when running the CLI and its tests.
Install backend dependencies into its own environment with
`backend/.venv/Scripts/python.exe -m pip install -r requirements.txt`.

For the CLI, create a MySQL database named `safevault` (with `utf8mb4` encoding),
copy the root `.env.example` to `.env`, and supply your MySQL credentials.
Run `python main.py`. Table creation happens at startup. Passwords are entered
without terminal echo; spaces in passwords are preserved.

Existing SHA-256 master-password verifiers are upgraded to salted PBKDF2 after a
successful login. This preserves the existing salt and encryption key, so saved
Fernet tokens remain readable. New and edited passwords are always encrypted.
Previously stored plaintext values from the old edit bug must be entered again
through the edit command; they cannot be decrypted as Fernet tokens.

For Django, copy `backend/.env.example` to `backend/.env` if no configuration
exists, and supply a random `DJANGO_SECRET_KEY` and your PostgreSQL credentials.
The CLI's `MYSQL_*` configuration is separate from Django's PostgreSQL `DB_*`
configuration. Use the backend virtual environment consistently: the default
`python` on this machine is a different Python installation. Run
`backend/.venv/Scripts/python.exe -B backend/manage.py migrate`, then
`backend/.venv/Scripts/python.exe -B backend/manage.py runserver`. Add deployment hostnames to
`DJANGO_ALLOWED_HOSTS` when needed.

For the frontend, run `npm ci` followed by `npm run dev` in `frontend`.
Development requests to `/api` are proxied to Django on `127.0.0.1:8000`.
For production, route `/api` to Django at the web server, or set
`VITE_API_BASE_URL` before building and allow that frontend origin in Django's
CORS configuration.

## Verification

Run from the repository root:

```powershell
python -m unittest discover -v
backend/.venv/Scripts/python.exe -B backend/manage.py check
backend/.venv/Scripts/python.exe -B backend/manage.py test accounts vault --settings=config.test_settings -v 2
```

The SQLite in-memory suite skips the six PostgreSQL concurrency tests.
To run all backend tests on PostgreSQL, use the explicit integration settings:

```powershell
backend/.venv/Scripts/python.exe -B backend/manage.py test accounts vault --settings=config.postgres_test_settings -v 2
```

This requires permission to create a PostgreSQL database. Django creates and
removes a fresh `test_velnar_<random UUID>` database for the test run, separate
from `safevault`. Never point the test database at an existing vault database.

Run from `frontend` (Node.js 24 or later):

```powershell
npm test
npm run build
npm run lint
```

The default tests use mocked CLI connections and isolated Django settings. They
do not write to the real vault. To opt into the read-only MySQL connectivity test,
set `SAFEVAULT_TEST_MYSQL=1` and run `python -m unittest test_mysql -v`.

Keep `.env`, database files, virtual environments, and generated files out of
source control. Ignore rules do not remove files already tracked in Git.

## Architecture and current scope

See [the audit and phased plan](docs/project-audit.md),
[account authentication and deployment settings](docs/authentication.md), and
[encrypted storage v1](docs/encryption-format.md). The vault-entry schema contains
no plaintext title, username, password, website, notes, category or favorite
columns. Clients encrypt these fields together and search/filter locally
after unlock. The server cannot verify encryption or GCM tags without keys;
encoding validation alone is not proof of encryption.

Open **Sign in** or **Settings** in the frontend to create an account, sign in,
sign out, or revoke another browser's session. Use the same hostname consistently
(for example, `127.0.0.1:5173`) so host-only cookies work through Vite's API proxy.
The account password is separate from the vault master password. No vault or
real password entry is created during account registration.

In **Account → Recovery email**, enter your current account password and verify
your email address. **Forgot your account password?** requests a reset link by
username. Run the [account recovery mail worker](docs/authentication.md#recovery-email-and-account-password-reset)
for queued messages. The reset returns you to sign-in. Open the vault with your
master password after signing in.

Open **All Passwords** after signing in to create or unlock your vault. All entry
fields are encrypted before upload. Security Center configures auto-lock, which
is enforced in the client. See [Phase 3 implementation and limits](docs/phase3-web-vault.md).

Open **Backups** while the vault is unlocked to prepare and download an encrypted
snapshot with a separate backup password. To restore, choose the file, enter its
backup password, review the local preview, then explicitly restore as new copies.
Existing entries are preserved. Repeating the same backup in the same destination
does not create duplicates. See [backup format and restore semantics](docs/backups.md).

Open **Security Center** for a local review of weak password patterns and exact
password reuse, then choose Review to edit a flagged entry. The dashboard shows
live review counts; the generator supports configurable character groups and
the entry list supports sorting and clearing filters. See
[local password health](docs/password-health.md). Before deployment, run the
[production configuration checks](docs/deployment-checks.md).
For a hosted beta, use the [Linux Compose deployment guide](docs/compose-deployment.md).
For local testing, use the [isolated beta launcher](docs/local-beta.md).

**Secure Notes** and **Payment Cards** store encrypted notes, cardholder names,
card numbers and expiry dates. Unlocked vaults refresh changes from other
devices. Use **Offline Backup** to read a downloaded encrypted archive with its
backup password. [Backup and recovery guide](docs/backups.md)

Add or download [encrypted attachments](docs/attachments.md) from an entry.
Attachments stay with the entry through Trash, key rotation and backups.

Open **Security Center → Change master password** while unlocked to replace
the vault's master password. The current password is checked locally; entries
and Trash preserve their encrypted bytes. The vault locks on success and uses
the new password on its next unlock. Account and backup passwords are separate.
See [master-password changes and their limits](docs/master-password.md).

Set up a **Vault recovery key** in Security Center to reset a forgotten master
password while preserving entries and Trash. Save it outside the vault. See
[vault recovery and its limits](docs/vault-recovery.md).

Use **Security Center → Rotate vault encryption key** to encrypt all records,
including Trash, under a fresh key and set a new master password. Other devices
must unlock again. See [key rotation and deployment requirements](docs/key-rotation.md).

**Move to Trash** now keeps an encrypted entry recoverable. Open **Trash** to
restore it or explicitly delete it forever. Trash has no automatic expiry and
counts toward vault capacity. New backups include active entries only. Apply the
additive backend migration before using this frontend; see
[Trash behavior and API compatibility](docs/trash.md).

An already unlocked vault can save new or edited entries when the connection
drops. If it locks, use the master password to reopen the last synced entries
offline in the same tab. Queue moves to Trash and restores, and review them
alongside edits in **Local changes**. Permanent deletion requires a connection.
If another device changed an edited entry, keep the draft as a separate copy
or discard it.
[Offline editing guide](docs/offline-edits.md)

Public release requires an independent security audit and hosted deployment
validation.
Use synthetic test entries. Existing CLI files, Fernet data and legacy databases
have not been migrated or removed. The local `backend/.env` remains untracked
and ignored; its historical Git copies have not been removed.
