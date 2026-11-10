# Offline editing and device conflicts

Sign in and unlock the vault while online. If the connection drops, you can
still add or edit passwords, notes and cards, including attachments. A completed
save appears under **Local changes** until the server confirms it. The vault list
shows the last known server versions. Open **Review draft** to read the local
version and download its attachments.

While the vault is unlocked, the browser retries on reconnect and during regular sync checks. Use
**Sync now** to retry manually. Updates require the server's original entry
revision, Trash state version and vault key version to match. If another device
edited, trashed or removed the original, the server version takes precedence
in the vault list and your draft stays available. Choose **Save draft as new
copy** to create a separate entry, or **Discard local change** to remove the
browser copy. A discarded draft may already have reached the server if a save
was in flight or its response was lost. An exact encrypted match confirms an
earlier save without sending it again.

Moves to Trash and restores also appear under **Local changes** while queued.
The active list and Trash continue to show the last confirmed server state. On
reconnect, a move or restore requires matching content revision, Trash state
version and key version. A different server revision or Trash state leaves the
action in conflict. Discard it and review the current entry before requesting
another change. A transition confirmed at the exact next state version and with
unchanged ciphertext is acknowledged without sending it again.

IndexedDB stores encrypted envelopes and sync metadata such as account and
vault identifiers, key version, and the requested Trash action. Entry content
remains encrypted and unwrapped keys stay in memory. Up to 32 pending changes and 16 MiB of
encoded ciphertext are allowed per vault, with one pending change per entry.
Clearing site data removes the queue. Browser storage restrictions or quota
errors can also prevent local saves. Reload older tabs after updating so they
can open the upgraded queue.

Auto-lock and manual lock clear decrypted content and the unwrapped data key.
If the connection is unavailable, enter your master password again in the same
tab to read the last synced entries and resume saving drafts. The tab retains
only the wrapped key and encrypted entries in memory for this purpose. Closing
or reloading the tab, signing out, or switching vaults clears this copy. Drafts
still survive reloads in the same browser and origin. After a reload, reconnect
before opening the vault.

Before syncing drafts from an offline unlock, the client checks current access
and the vault's key and master-password wrapper. A revoked session or a changed
wrapper closes the offline vault. Remote changes take effect in this tab once
the server can be reached.

Permanent deletion, backup export and recovery operations require the server. Backups
contain confirmed server records. Sync drafts before rotating the vault key.
If another device already rotated it, drafts encrypted with the previous key
stay in the browser but cannot be opened or synced with the new key.
