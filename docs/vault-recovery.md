# Recovering a vault with a recovery key

While the vault is unlocked, open **Security Center → Vault recovery key**.
Enter the current master password. Save the displayed key somewhere you can
reach without the vault and confirm activation. The key is shown only during
setup. Canceling before activation leaves any existing key in place. The same
panel lets you replace or disable a key.

If you forget the master password, sign into the account, select the vault,
and click **Use a recovery key**. Paste the entire key and choose a new master
password. Recovery preserves entries and Trash, locks the vault, and consumes
the active recovery key. Unlock with the new password and set up a new key.
Account email recovery only restores access to the account; it does not replace
the vault's master password or recovery key. Backup passwords remain separate.

If a recovery response is lost, refresh the vault list and try the new master
password. If it does not work and recovery is still available, retry with the
saved recovery key. The client does not automatically replay the request.

## Storage and limits

The browser generates a random 32-byte secret and displays it as `SV1-` followed
by unpadded Base64url. It uses that secret to AES-256-GCM wrap the existing vault
data key with a random 12-byte nonce. The recovery envelope authenticates the
vault ID and data key version as associated data. The browser sends only the
opaque envelope, expected state and a replacement master wrapper when recovering.
The printable key and master passwords do not go to the server or browser storage.

The setup and recovery endpoints require an authenticated owning session and
CSRF and have a per-account request limit. They compare the current master and
recovery wrappers and key version under a database row lock. The server cannot
verify possession of a client-side secret from ciphertext. The browser
authenticates the recovery envelope and all active and trashed entries before
submitting a reset. Replacing the master wrapper and clearing the recovery
wrapper happen in the same transaction.

An ordinary master password change preserves the recovery key. Data key rotation
invalidates it; set up a new one afterward. Disable, replacement and consumption
remove the online recovery envelope, but someone who already copied both an old
envelope and its printable key can still obtain the corresponding data key. If
that may have happened, rotate the vault encryption key.

Apply migration `vault.0006` and deploy the backend and frontend together. Older
vaults start with recovery disabled. The backup file format is unchanged.
