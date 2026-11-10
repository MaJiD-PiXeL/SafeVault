# NEXORA SafeVault encrypted storage v1

The product was renamed from VELNAR. The `velnar.safevault` wire-format and AAD
strings below are permanent v1 compatibility identifiers, not display branding.
Do not rename them: existing vaults and backups depend on their exact bytes.

Status: client encryption and authenticated vault HTTP writes are implemented
and tested. Independent security review is pending; use synthetic test entries
in this development build. This specifies standard primitives, not a new
cryptographic algorithm. See `phase3-web-vault.md` for limits and validation.

## Trust boundary and authentication

Django stores account identities, ownership, crypto parameters and opaque
ciphertext. It must never receive the vault master password, unwrapped keys or
plaintext entry fields. Retain Django's existing user model via
`settings.AUTH_USER_MODEL`; references remain swappable. The master password is
distinct from the server-side account password. Phase 2 implements account
authentication and session/CSRF controls (see `authentication.md`); account-password reset must
not claim to recover a vault's encryption key.

The server sees vault/entry identifiers, account identity, timestamps, revision
numbers, entry counts and ciphertext lengths. Trash adds a visible deletion
timestamp and lifecycle counter. This is not metadata-free storage.
TLS protects transport. Client compromise/XSS can expose an unlocked vault.
No encryption keys or decrypted data belong in logs, localStorage, telemetry,
URL parameters or exception messages.

## Encoding and fixed profile

Binary values use canonical RFC 4648 **standard** Base64 with padding and no
whitespace (not Base64url). UUIDs use lowercase hyphenated strings. Integers
use decimal ASCII without leading zeroes in authenticated data (AAD).

| Vault field | v1 value |
| --- | --- |
| `format_version` | `1` |
| `cipher` | `AES-256-GCM` |
| `kdf` | `argon2id` |
| `kdf_version` | `19` (Argon2 v1.3) |
| `kdf_memory_kib` | `65536` (64 MiB) |
| `kdf_iterations` | `3` |
| `kdf_parallelism` | `4` |
| `kdf_salt` | 16 CSPRNG bytes, Base64 encoded |
| `wrap_nonce` | 12 fresh CSPRNG bytes, Base64 encoded |
| `wrapped_key` | 32 encrypted key bytes followed by a 16-byte GCM tag, Base64 encoded |

Client derivation: Argon2id(master password encoded as UTF-8, decoded salt,
the parameters above, **32-byte output**). Do not trim or normalize passwords.
Use an established Argon2id library with test vectors; run expensive work in a
worker. Clients must enforce the fixed profile before derivation to prevent
untrusted parameters from forcing excessive allocation or a downgrade.

Generate an independent random 32-byte vault data key. Encrypt that key with
AES-256-GCM under the derived wrapping key and `wrap_nonce`. The exact wrap AAD
is the UTF-8 encoding of the following string, with placeholders substituted:

```text
velnar.safevault:1:wrap:{vault_uuid}:argon2id:19:65536:3:4:{kdf_salt}
```

`kdf_salt` in this string is the canonical Base64 text stored on the vault.
Generate a new salt and independent data key for each vault. Never reuse a
nonce under the same key. The explicit [master-password change protocol](master-password.md)
can replace the wrapping salt, nonce and encrypted data key under a vault lock
and comparison against the expected current wrapper. The data key itself stays
unchanged. [Data-key rotation](key-rotation.md) replaces the key and re-encrypts
the entries. Ownership transfer remains unsupported.

## Entry envelope

The client generates the entry UUID **before encryption**. Every revision gets
a fresh random 12-byte nonce and encrypts the complete UTF-8 JSON payload using
AES-256-GCM under the vault data key, with a full 16-byte tag appended to the
ciphertext. Store the result in `ciphertext` and the encoded nonce in `nonce`.
Entry text is limited to 64 KiB. The decoded ciphertext maximum is 3 MiB plus
the 16-byte tag to allow encrypted attachments. The storage validator checks
encoding and size, not authenticity.

Exact entry AAD (UTF-8, no trailing newline):

```text
velnar.safevault:1:entry:{vault_uuid}:{entry_uuid}:{revision}
```

First revision is `1`; updates encrypt using `expected_revision + 1`. UUIDs,
revision and vault identity must match on decryption. Reject authentication-tag
failure without showing partial plaintext. No client-provided AAD is persisted;
clients reconstruct it using these rules.

Trash leaves the encrypted `revision`, nonce and ciphertext unchanged. Its
separate `state_version` increments on move/restore, and `deleted_at` records
whether the entry is in Trash. These fields are server metadata, outside GCM
AAD. Writes check both content revision and lifecycle version; see
[Trash semantics](trash.md). The v1 payload and AAD strings remain unchanged.

The decrypted JSON schema is:

```json
{
  "schema_version": 1,
  "title": "Example",
  "username": "user@example.test",
  "password": "client-only value",
  "website": "",
  "notes": "",
  "category": "Personal",
  "favorite": false
}
```

`title` and `password` must be nonempty strings. `username`, `website`, `notes`
and `category` are optional strings, defaulting to `""`; `favorite` is an
optional Boolean defaulting to `false`. Clients validate these types and the
schema version after decryption. None of these fields has a plaintext database
column. Search, favorites and category filtering happen locally after unlock;
the server offers ownership-scoped encrypted-record synchronization only.

For a record with files, the client encrypts a version 3 payload containing
the original version 1 or 2 record and its [attachments](attachments.md).
The envelope and AAD are identical for every supported payload version.

## Persistence, nonce lifetime and versioning

All vault HTTP writes go through `vault.services`, with the user obtained
from authenticated server context. Never accept `owner` from request data.
Services reject inactive/anonymous users, scope reads and writes to ownership,
lock rows in transactions, and reject stale revisions before modifying data.
Database constraints enforce the profile, nonce uniqueness and revision bounds.
UUIDs alone are not authorization.

Each successful encrypted write reserves `(vault, nonce)`. Reservations remain
after updates and entry deletion, until the entire vault/key is deleted. The
reservation table contains no ciphertext or entry references. Never purge its
rows while that vault key is live. This catches reuse submitted to the server;
offline clients must also keep nonces unique before synchronization. A rejected
write must be re-encrypted with a fresh nonce. Concurrent uniqueness failures
are mapped to generic HTTP 409 conflicts by API serializers/views.

Direct ORM/bulk updates are trusted administrative operations and can bypass
application validation or reservations; they must not be used for API writes.
Syntactically valid Base64 plaintext is indistinguishable from ciphertext to a
keyless server. Only a correct client can ensure encryption and verify tags.
The authenticated API accepts explicit encrypted-envelope fields only; plaintext
field names, unknown fields and ownership overrides are rejected.

Unknown formats are rejected, never silently interpreted as v1. Changing
primitives, KDF parameters or payload schemas requires explicit versioned
migrations, client capability checks and shared test vectors. Monotonic server
revisions prevent accidental lost updates. Malicious-server rollback detection
remains future work. The browser queues [encrypted offline drafts](offline-edits.md)
and preserves both versions when revisions conflict. It can queue recoverable
Trash actions. Permanent deletion requires a connection.

## References

- [RFC 9106, section 4: Argon2id profiles](https://www.rfc-editor.org/rfc/rfc9106.html#section-4)
- [Cryptography AESGCM: nonce uniqueness and ciphertext/tag layout](https://cryptography.io/en/latest/hazmat/primitives/aead/#cryptography.hazmat.primitives.ciphers.aead.AESGCM)
- [Django model validation: save does not call full_clean automatically](https://docs.djangoproject.com/en/6.0/ref/models/instances/#validating-objects)
