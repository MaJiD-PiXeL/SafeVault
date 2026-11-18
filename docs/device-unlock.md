# Optional device unlock

After unlocking, open **Security Center → Device unlock** and confirm the
master password. A compatible platform authenticator creates a passkey and
requires local user verification. The operating system may offer fingerprint,
face recognition or its device PIN. The site cannot require a particular
biometric method or claim that a physical biometric was used.

This feature requires WebAuthn's PRF extension in both the browser and passkey
provider. Unsupported providers fail without saving a vault key. This is a
local encryption ceremony, not account passkey authentication: account sign-in
and any enabled TOTP protection still apply.

The PRF output is imported as a nonextractable AES-256-GCM key. It encrypts the
existing 32-byte vault data key. Only credential ID, random PRF input, nonce,
encrypted key and a SHA-256 binding are saved in this origin's localStorage,
scoped to account and vault. The binding covers origin, account ID, vault ID,
key version and complete master-password wrapper, and is also GCM additional
authenticated data. Neither the master password nor a plaintext key is saved.
Temporary raw data-key and PRF byte arrays are overwritten. JavaScript and
browser memory cannot provide forensic erasure guarantees.

Every unlock fetches current vault metadata. A changed master-password wrapper
or data-key version invalidates device unlock. Account changes, locking and
cancellation prevent late ceremonies from publishing plaintext. Remove the
local setup in Security Center and set it up again after a password change.
Removing the local wrapper does not delete the passkey from the OS/provider;
delete that credential in the provider's own settings if wanted.

A synced passkey may be available on another device, but the encrypted local
wrapper is not synced by SafeVault. This feature expands trust to the device
unlock method and passkey provider. Keep a master password and recovery key.
Storage clearing removes the convenience setup. XSS or a compromised client
origin remains outside this protection.

Crypto interoperability, wrong PRF, wrapper changes, corruption and cancellation
are tested with mocked authenticators. Actual Windows Hello, Android biometrics
and provider PRF compatibility still need device testing. Embedded WebViews
may lack the required API; use the master-password path in that case.

[WebAuthn PRF](https://www.w3.org/TR/webauthn-3/#prf-extension)
