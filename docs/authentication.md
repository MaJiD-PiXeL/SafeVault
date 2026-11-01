# Account authentication — Phase 2

Account sign-up, sign-in, sign-out and browser-session revocation are implemented.
Vault unlock and encryption are implemented separately in the client (Phase 3).
No master password field or vault write is accepted by these account APIs.

## Endpoints

All paths are under `/api/auth/`. Responses use `Cache-Control: no-store`.

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `session/` | Return `{user, csrfToken}`; user is null when signed out |
| POST | `register/` | Create an account and establish a new browser session |
| POST | `login/` | Authenticate an existing account and rotate its session/CSRF |
| POST | `logout/` | Invalidate the current database session and rotate CSRF |
| GET | `sessions/` | List this account's unexpired product browser sessions |
| DELETE | `sessions/<uuid>/` | Revoke only a session belonging to this account |

Registration and login accept exactly `username` and `password`. Usernames are
3–50 ASCII letters/numbers/dots/underscores/hyphens, begin with a letter or
number, and are normalized to lowercase. Account passwords are not trimmed;
the maximum is 1,024 characters. Registration uses Django password validation,
including a 12-character minimum, common-password and similarity checks.
Passwords are hashed with Django's salted PBKDF2 hasher, never SHA-256 alone.
Duplicate registrations return a generic 400 error. Invalid credentials,
unknown accounts and inactive accounts share the same login error.

The **account password is sent to Django** over the authenticated HTTPS origin
in production. It must differ from the **vault master password**, which must
stay on the client. Signing in does not unlock or create a vault. Password reset,
account deletion, email verification, MFA and account credential changes are not
implemented, and no key recovery is implied.

## CSRF and cookies

The browser first calls `GET session/`, with `credentials: include`, to receive
a masked CSRF token. It sends that token in `X-CSRFToken` for every mutation,
including anonymous registration and login. The APIs explicitly enforce CSRF
in addition to DRF session authentication. Cross-origin requests must also pass
the configured Origin checks. JSON is the only accepted request body format.

Session and CSRF cookies are HttpOnly, host-only and SameSite=Lax. JavaScript
keeps only the masked CSRF token in memory; no bearer token or account password
is persisted in localStorage/sessionStorage. Login and logout return the new
CSRF token. A failed CSRF mutation is never automatically replayed. A later
explicit attempt refreshes its token, and slow session checks cannot overwrite
a token rotated by a newer sign-in.

Sessions expire after 30 minutes without automatic renewal on reads; cookies
also expire when the browser closes, subject to the browser's own session
restoration behavior. A maximum of ten product sessions is retained per account;
a new sign-in revokes the oldest excess sessions and preserves the current one.
Session list UUIDs are independent of secret cookie values. Revocation deletes
the database session, so the next request from that browser is unauthenticated.
An already executing request may finish before revocation takes effect.

The UI checks session state on focus, visibility changes and once per minute.
Revoked/expired sessions return the account interface to signed out. Django
admin sessions created outside the product sign-in flow are not listed as
product sessions. Client vault auto-lock now covers manual lock, inactivity,
optional hidden-tab locking, pagehide, account change, logout and auth loss.

## Login protection and request budgets

`django-axes==9.0.0` uses its database handler and guards Django authentication,
including admin login. Ten failed attempts by a username **or** peer IP cause
a 15-minute lockout. Attempts made while locked out do not extend that timer;
the successful login path resets matching failure counters. Lockouts return
HTTP 429 with a generic message and Retry-After. Temporary username lockout can
also prevent the account's legitimate user from signing in during that period.

An additional atomic database request budget limits all login requests to
30 per minute per peer IP, and registrations to five per hour per peer IP.
Malformed requests count toward these budgets before body validation. Fixed
windows can permit two windows' budgets around a boundary; these budgets are
not a comprehensive denial-of-service defense. Counters contain HMAC identifiers
made with Django's `salted_hmac`, rather than raw IP addresses. Conditional SQL
updates enforce the budget across workers; PostgreSQL concurrency tests cover it.

Peer addresses come only from `REMOTE_ADDR`. Untrusted `X-Forwarded-For` is
ignored. Behind a proxy, configure a trusted peer-address chain at the server
boundary and ensure clients cannot reach Django directly; otherwise all clients
share the proxy address and its limits. Edge request limits remain necessary
for a production deployment, especially against distributed traffic.

Axes stores account/IP attempt metadata for lockout decisions. Its log messages
mask username/IP/password values; successful-login trails and per-failure trail
logging are disabled. API JSON bodies are not stored as Axes form POST data.
Do not enable raw-body logging, credential telemetry or unfiltered exception
capture in the app, proxy or external monitoring tools. DEBUG must remain off
in production.

## Configuration and maintenance

`DJANGO_ENV` must be `development` or `production`. Development permits local
HTTP so the existing Vite proxy works. Production forces secure cookies, HTTPS
redirects, HSTS (initially one hour) and refuses DEBUG=True. Configure
`DJANGO_ALLOWED_HOSTS`, `DJANGO_CORS_ALLOWED_ORIGINS` and
`DJANGO_CSRF_TRUSTED_ORIGINS` explicitly. CORS uses explicit credential-capable
origins, never a wildcard. Same-origin web hosting is the preferred deployment.
Cross-site hosting requires a separate reviewed cookie/authentication design.

At a TLS-terminating reverse proxy, configure Django's proxy HTTPS detection only
after ensuring the proxy removes/overwrites client-supplied forwarding headers.
The app deliberately does not trust arbitrary forwarded HTTPS/IP headers.

Run migrations before using the account pages. Periodically run:

```powershell
backend/.venv/Scripts/python.exe -B backend/manage.py prune_auth_state
```

The command removes only expired sessions, expired request windows and expired
Axes attempt counters. It does not delete accounts, vaults or encrypted entries.
No scheduled automation was added. For operator-directed lockout recovery, Axes
provides its `axes_reset_username` and `axes_reset_ip` management commands.

The local environment could reach GitHub but could not resolve PyPI's file host.
For this run only, Axes was built from its official `9.0.0` source tag using
existing build tools, with that tag version set explicitly in temporary build
metadata instead of the unavailable SCM build plugin. Runtime source was not
modified. The local wheel and build source are confined to the ignored `.venv`.
Normal installations use the pinned PyPI requirement; `pip check` passes here.

`backend/.env` has been removed from the Git index and remains on disk, ignored
by Git. Its historical commits still exist; untracking does not remove secrets
from history or rotate them. No history rewriting was performed.

## Verification

```powershell
backend/.venv/Scripts/python.exe -B backend/manage.py test accounts vault --settings=config.test_settings -v 2
backend/.venv/Scripts/python.exe -B backend/manage.py test accounts vault --settings=config.postgres_test_settings -v 2
```

The PostgreSQL suite uses a fresh random test database, not the real vault.
Coverage includes account validation/hashing, login CSRF, untrusted origins,
session/token rotation, account isolation, session expiry/revocation/caps,
registration rollback, admin/API lockouts, expired-state cleanup, atomic request
budgets and vault write concurrency. Frontend transport tests cover CSRF
bootstrap/rotation/races, explicit payloads, credentialed fetches, failed-request
handling, session metadata validation and revocation. The forms were inspected
in the browser at desktop and 320px widths. This is not an independent audit.

References: [Django CSRF](https://docs.djangoproject.com/en/6.0/ref/csrf/),
[Axes configuration](https://django-axes.readthedocs.io/en/stable/4_configuration.html),
[DRF throttling limitations](https://www.django-rest-framework.org/api-guide/throttling/).
