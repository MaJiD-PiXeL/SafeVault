# Account two-step verification

In **Account → Two-step verification**, enter the current account password,
add the displayed setup key to a TOTP authenticator, then confirm with a code
and the account password. Setup expires after ten minutes. Ten recovery codes
are displayed once; save them outside the vault before leaving this screen.
No third-party QR service receives the setup secret. Manual setup uses SHA-1,
six digits and a 30-second period, following RFC 6238.

Sign-in accepts the account password plus a fresh authenticator code or an
unused recovery code. It creates no authenticated session before both factors
succeed. A used time step cannot be reused; the clock window is at most one
step either side. Verification and recovery-code consumption hold the user's
PostgreSQL row lock, including during concurrent sign-ins. Per-IP login budgets
and a ten-attempt, five-minute per-user second-factor budget apply. Failed
management requests retain their separate hourly budget.

Seeds are encrypted with Fernet under a domain-separated key derived from the
Django secret, and recovery codes contain 128 random bits and are stored only
as SHA-256 hashes. Server operators can decrypt TOTP seeds. TOTP protects account
sign-in; it does not change client-side vault encryption or resist real-time
phishing. Keep the server clock synchronized.

Enabling/disabling verification revokes other account sessions. Disabling
requires the account password and a fresh authenticator or recovery code.
Email-based password reset **keeps the second factor enabled**. Losing both the
authenticator and all recovery codes prevents account sign-in; there is no
email bypass. The vault recovery key is separate and does not disable TOTP.
Recovery-code regeneration is currently done by disabling and setting up the
factor again; do this only on a trusted device.

Django admin has an authenticator/recovery-code field and requires an enabled
second factor for password sign-in. Set it up through the account UI first.
Admin sessions join the regular revocation list and ten-session cap.

Apply `python backend/manage.py migrate accounts` using the backend environment
before starting this frontend/backend pair. For Django-key rotation, re-encrypt
every `SecondFactor.encrypted_secret` under the new key in the same operational
change. The local rotation tool performs this automatically. Merely replacing
the Django key after enabling TOTP makes the seed unreadable. Django
`SECRET_KEY_FALLBACKS`, when set through trusted settings code during a planned
rotation, can temporarily read old encrypted seeds; do not retain compromised
keys as a permanent fallback.

Tests include RFC vectors, CSRF, expiry, replay, one-use recovery codes, admin
sign-in, session revocation and a PostgreSQL two-connection race. Independent
security review and real authenticator-device validation remain required.

[RFC 6238](https://www.rfc-editor.org/rfc/rfc6238.html)
