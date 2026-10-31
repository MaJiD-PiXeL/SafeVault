# SafeVault

The Python CLI manages encrypted passwords in MySQL. The React frontend is a
sample interface; the Django backend currently exposes only read-only metadata
and liveness endpoints. The frontend does not store or authenticate real vault data.

## Setup

Install Python dependencies with `python -m pip install -r requirements.txt`.
Use the same Python environment when running the CLI and its tests.

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
configuration. Run `python backend/manage.py migrate`, then
`python backend/manage.py runserver`. Add deployment hostnames to
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
python backend/manage.py check
python backend/manage.py test vault --settings=config.test_settings -v 2
```

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
