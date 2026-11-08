# Encrypted attachments

Open a password, secure note or payment card and choose files under **Attachments**.
Save the entry to keep them. An entry accepts up to three nonempty files, at most
1 MiB per file and 2 MiB total. Filenames must be portable and at most 180
characters. An attachment counts toward the vault's existing storage limit.

Use the download button in the entry, Trash, or the offline backup reader to
save a copy on your device. SafeVault does not preview or run file content. A
downloaded copy is outside the vault and remains on your device after lock.
Removing an attachment takes effect when you save the entry. Previous backups
can still contain a copy. A backup includes attachments on active entries;
restore a trashed entry first to include it in a new backup.

## Encryption and compatibility

The browser reads files locally and stores their names, sizes and Base64 bytes
inside the same authenticated ciphertext as the entry. The API receives only
the existing entry envelope. It can observe ciphertext length and normal entry
metadata, but has no separate attachment fields or file routes. Browser object
URLs are created only for explicit downloads and revoked shortly afterward or
when the view closes. The application does not cache plaintext attachments.

Entries without attachments retain their v1 password or v2 note/card payload.
Entries with attachments use a v3 payload with exactly `schema_version`,
`record` (the original v1/v2 payload), and `attachments` (an array of objects
with exactly `name`, `size` in bytes, and canonical Base64 `content`). The
client verifies each file length and both size limits. The original text fields
remain limited to 64 KiB. The outer encrypted envelope and associated data
remain unchanged. The same inner payload is supported in the v1 backup file.

Apply migration `vault.0007` and update the backend and all clients before
saving attachments. Older clients and offline readers cannot open the new
payload. The backend accepts entry ciphertext up to 3 MiB plus the 16-byte tag
before Base64 encoding; the total vault quota stays 32 MiB of encoded ciphertext.

Tests verify exact file bytes across encryption, download, backup, and rotation.
A live API rehearsal with two separate sessions and a disposable database
verified save and edit with 2 MiB of files, device sync, Trash, key rotation,
offline backup opening, and restore to a separate vault.
