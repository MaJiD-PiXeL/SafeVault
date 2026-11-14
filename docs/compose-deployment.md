# SafeVault on a Linux host

The Compose package runs Caddy, Gunicorn, PostgreSQL and the recovery mail
worker. Caddy serves the built frontend and Django's static assets. It
forwards API and admin traffic over a private Unix socket. Gunicorn runs as a
dedicated user and accepts HTTPS metadata from Caddy over that socket.
PostgreSQL is reachable through the internal storage network. The app's
database role owns its database and has ordinary login privileges.

## Prepare the host

Use a Linux host with Docker Compose v2, a DNS hostname you control and an SMTP
sender approved by your provider. For a private beta, restrict access to
participants at the network boundary. Give Caddy access to ports 80 and 443 for
certificate issuance. This configuration assumes Caddy receives client traffic
directly. An additional proxy or CDN needs a reviewed client-IP configuration.

Copy `deploy/.env.example` to `deploy/.env` and set the hostname and SMTP values.
The port bindings default to loopback. Set `VAULT_BIND_ADDRESS=0.0.0.0` when the
host firewall and beta access rules are ready.

Create an operator-only `deploy/secrets/` directory with mode 0700. Place fresh
values in `django-key`, `postgres-admin-password`, `database-password` and
`smtp-password`. Use independent random values for the first three and the
provider's credential for SMTP. Restrict access on the host through the
directory permissions. Each file must be readable by its recipient container.
For Docker Compose file mounts, mode 0444 inside the 0700 directory provides
this on a standard rootful Linux engine. Use the mounted file permissions your
engine requires if it remaps users. The build context and Git ignore the local
configuration and secret files.

Earlier Git history contains a Django key and PostgreSQL password. Use fresh
values for new environments. Rotate each historical value wherever it is still
used. Rotating the Django key invalidates existing sessions and account email
links. A database password change on an existing volume requires updating the
role in PostgreSQL as well as replacing its secret file. The initialization
script creates the application role only on a fresh volume.

## Start and verify

Run from the repository root.

```sh
docker compose --env-file deploy/.env config --quiet
docker compose --env-file deploy/.env up --build -d
docker compose --env-file deploy/.env ps -a
```

The migration service checks production settings and applies migrations before
Gunicorn and the worker start. Caddy waits for the API's readiness check.
The check allows the documented HSTS warnings while requiring configuration
errors to be resolved. Review the strict check separately for the chosen host.

When upgrading an existing deployment to enable key rotation, apply the migration
and replace all API workers before exposing the new frontend. See
[key rotation deployment requirements](key-rotation.md#protocol-and-deployment)
before planning a rollback.

```sh
docker compose --env-file deploy/.env run --rm --no-deps migrate \
  python manage.py check --deploy --fail-level WARNING
```

Monitor `GET /api/health/` for process liveness and `GET /api/ready/` for database
readiness. Alert on repeated readiness failures, migration failures and mail
delivery errors. Inspect the worker's status with
`docker compose --env-file deploy/.env logs worker`. It polls for recovery
requests and prunes expired authentication state hourly.

On the actual HTTPS origin, use synthetic entries to verify sign-in, account
email delivery and reset, vault unlock, Trash and backup restore. Confirm that
the API sends `Cache-Control: no-store` and session cookies are secure. Plan
periodic PostgreSQL backups to protected storage and rehearse restoring one to
a separate database. The in-app encrypted export covers a user's active vault
entries. A PostgreSQL backup also captures account and operational state.

Host deployment, public TLS issuance and SMTP delivery require validation in
the target environment. Schedule an independent security review before public
use with real passwords.

Local checks cover the Caddy configuration, Django production settings,
database readiness and a two-session rehearsal against a disposable database.
Run the complete Compose startup and HTTPS smoke test on the Linux host.

## Automated Compose smoke test

The [GitHub verification workflow](../.github/workflows/verify.yml) starts the
same Compose file on a disposable runner with `safevault.localhost` bound to
loopback. It trusts the temporary Caddy CA for its test requests and checks the
frontend, offline shell, database readiness, CSRF registration, secure cookies,
encrypted entry creation and paginated reads, and sign-out. The workflow removes
its Compose volumes after the run. Verify mail delivery and public certificates
on the target host.

[Docker startup ordering](https://docs.docker.com/compose/how-tos/startup-order/) ·
[Caddy HTTPS](https://caddyserver.com/docs/automatic-https) ·
[Gunicorn proxy deployment](https://gunicorn.org/deploy/)
