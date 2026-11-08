# SafeVault local beta

Build the frontend and run the local launcher from the repository root using the
project's Python environment:

```powershell
npm --prefix frontend run build
backend/.venv/Scripts/python.exe deploy/local-beta.py --port 18010
```

Open `http://127.0.0.1:18010/` on the same computer. The launcher copies the build
to a fresh temporary directory, applies migrations to a new SQLite database,
and writes verification and account reset emails to the local mailbox shown in
its output. No email is sent over the network. The launcher ignores the project's
`.env` and binds only to loopback. Restarting creates a new test environment.

Use synthetic data. A local rehearsal checked account email verification and
password reset, vault recovery, the old master password and recovery key being
rejected after recovery, recovery after a lost response, preservation of active
and trashed records, and restoration of an earlier encrypted backup into a
separate vault. The mailbox contains MIME messages; open them in a mail reader
or decode the body as quoted-printable when extracting a link.

This launcher is for local testing. Use the [hosted Compose guide](compose-deployment.md)
to validate TLS, PostgreSQL, SMTP delivery and monitoring on a real host.
