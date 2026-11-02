# NEXORA SafeVault brand

SafeVault is the encrypted password workspace under the NEXORA identity.
The source is the existing chat **Build the NEXORA official website** and its
implementation in the neighboring `site` project, particularly
`static/nexora/DESIGN_SYSTEM.md` and `static/nexora/mark.svg`.

- Company/wordmark: NEXORA.
- Product: NEXORA SafeVault.
- Tagline: Beyond What Exists.
- Mark: the existing metallic N, copied unchanged to `frontend/public/nexora-mark.svg`.
- Typography: self-hosted Manrope variable (200–800), with its OFL license in
  `frontend/public/fonts/Manrope-OFL.txt`.
- Palette: obsidian `#08090B`, white `#FFFFFF`, titanium `#BFC3C8`, graphite
  `#25282D`, electric blue `#426BFF`. Blue is an interaction accent.

The existing React workspace layout and English interface are retained.
The website's marketing pages, demonstration achievements, account system and
company contact information are not imported into the password manager. No
verified contact information was supplied in that project; none is invented here.
Guest entries are explicitly sample data and use reserved example identities.
There is no shared login or SSO integration with the NEXORA marketing website.

## Compatibility

This is a presentation change, not a cryptographic migration. Keep these stable:

- `velnar.safevault:1:*` authenticated encryption AAD strings.
- `velnar.safevault.backup` v1 archive format and existing test vectors.
- Database names, schemas, IDs, encrypted entries, passwords and keys.
- Existing `velnar_session` / `velnar_csrf` cookies and request-budget HMAC domain.
- Legacy CLI verifier prefix, filenames, environment variables and test DB settings.

These names are internal compatibility contracts. A global search-and-replace
would make existing ciphertext unreadable or invalidate sessions. Existing
VELNAR-named backups continue to open; new downloads use
`nexora-safevault-backup-<timestamp>.json`. Original logo assets are retained for
history, and the dated audit is explicitly marked as a historical snapshot.

The current security-audit and development-build notices remain accurate.
