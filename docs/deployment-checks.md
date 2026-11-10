# Deployment configuration checks

The backend registers additional Django deployment checks. Run them in the
intended production environment, after configuring its environment variables:

```powershell
backend/.venv/Scripts/python.exe -B backend/manage.py check --deploy --fail-level WARNING
```

No database migration, data write or deployment is performed by this command.
Ordinary development `check` and `runserver` remain available with local settings.

| Check | Required configuration |
| --- | --- |
| `safevault.E001` | `DJANGO_ENV=production` |
| `safevault.E002` | Explicit `DJANGO_ALLOWED_HOSTS`; no wildcard, leading-dot subdomain rule, empty list or default loopback hosts |
| `safevault.E003` | Every CORS origin is explicit HTTPS, without credentials, path, query, fragment or development host |
| `safevault.E004` | The same restrictions for trusted CSRF origins |
| `safevault.E005` | DEBUG off, secure session/CSRF cookies, HTTPS redirects enabled |
| `safevault.E006` | A configured SMTP host when the production SMTP backend is used |
| `safevault.E007` | The public HTTPS frontend origin for recovery email links |
| `safevault.E008` | A sender address for account emails in `DJANGO_FROM_EMAIL` |

Django's built-in checks additionally cover weak/default secret keys, security
middleware and other deployment protections. Diagnostics do not print configured
origin/host values or secrets. An empty CORS/trusted-CSRF list is valid for
same-origin hosting; listing a frontend origin is only needed for a separate
trusted origin. Production must remove the development origins from `.env`.

Example shape (supply a new strong secret through the deployment's secret store):

```dotenv
DJANGO_ENV=production
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=vault.example.com
DJANGO_CORS_ALLOWED_ORIGINS=
DJANGO_CSRF_TRUSTED_ORIGINS=
DJANGO_ACCOUNT_LINK_ORIGIN=https://vault.example.com
DJANGO_FROM_EMAIL="SafeVault <no-reply@vault.example.com>"
DJANGO_SMTP_HOST=smtp.example.com
DJANGO_SMTP_PORT=587
DJANGO_SMTP_USERNAME=your-deployment-mailbox
```

Supply `DJANGO_SMTP_PASSWORD` through the secret store too. Production now uses
SMTP with STARTTLS and a ten-second timeout. Development uses the console
mailer. Schedule the [account recovery mail worker](authentication.md#recovery-email-and-account-password-reset)
and check that a synthetic account receives and can use both kinds of email.

`DJANGO_HSTS_INCLUDE_SUBDOMAINS` and `DJANGO_HSTS_PRELOAD` default to False. Django
reports warnings for these defaults. Enable them only after confirming that all
affected hosts support HTTPS and reviewing the long-lived effects of preload.
The existing initial HSTS duration remains one hour; enabling the preload flag
alone does not meet browser preload-list requirements or submit the domain.
Until those choices are reviewed, the strict `--fail-level WARNING` command
intentionally fails on the warnings; do not interpret them as a passing release.

Passing checks validates configuration, not the deployed network or product's
security. Before release, serve the built frontend over HTTPS, disable caching
of API responses, configure static assets and database access, verify backup
restore, and exercise session/CSRF behavior on the actual origin. At a reverse
proxy, trust forwarded HTTPS/IP headers only when the proxy overwrites them and
direct access to Django is blocked. These changes do not alter existing proxy
trust or publish the application. Master-password changes, data-key rotation and
[vault recovery](vault-recovery.md) are available. [Offline edits](offline-edits.md)
sync from the same browser. The independent security audit remains outstanding.

References: [Django deployment checklist](https://docs.djangoproject.com/en/6.0/howto/deployment/checklist/),
[Django system checks](https://docs.djangoproject.com/en/6.0/topics/checks/).
