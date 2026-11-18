# Local replay checks and paged decryption

The browser remembers the highest authenticated content revisions it has seen,
the corresponding ciphertext SHA-256 fingerprints, observed lifecycle versions,
historical master-password wrapper fingerprints and the highest data-key version.
Complete snapshots include Trash. An entry explicitly permanently deleted
through this browser is remembered as removed; reappearance of that UUID is rejected.
In-app backup restore uses fresh UUIDs, so it does not resurrect removed IDs.

The browser stops unlock or refresh when a snapshot reuses a previously replaced
wrapper, lowers a known key/content/state version, substitutes different
ciphertext at the same content revision/key version, or resurrects a removed
record. An absent record alone is not proof of deletion, since another tab may
have observed a newer snapshot. It never silently clears damaged or full local history. The guard runs
before publishing newly decrypted records and on background synchronization.

These checks are **local evidence of replay**, not global server integrity or
cryptographic freshness. A first device has no trusted history. Browser storage
can be cleared or changed by a compromised origin, and snapshots omitted before
this device observed them cannot be detected. Server-controlled lifecycle
metadata is not authenticated inside the current encrypted entry AAD. A server
can omit entries and claim a permanent deletion; the client cannot distinguish
that from an authorized deletion. Independent cross-device witnesses or an
authenticated append-only protocol would be needed for stronger protection.

History is scoped to account/vault in localStorage and contains no plaintext
entry fields. It retains at most 20,000 historical UUIDs and 1,000 wrapper
fingerprints. **Security Center → Browser vault history** has an explicit reset
acknowledgment for an intentional database restore. Reset locks the vault,
forgets its offline snapshot and trusts the next successful unlock as a new
baseline. Verify the restore and backup before doing this.
Close other vault tabs before resetting history. Web Locks serializes history
commits across tabs where supported; older browsers use an immediate
compare/write fallback and cannot provide the same cross-tab serialization.

Full reads now await decryption of each bounded API page before fetching the
next. No second full list of encrypted records is accumulated by the API during
streamed reads. Nothing is published until all pages authenticate and their
snapshot version/count/continuation checks pass. Existing adapters retain their
nonstreaming fallback. This is paged processing, not an unlimited streaming
vault: the final unlocked snapshot and encrypted offline copy still occupy
memory, and the existing 5,000-entry/32 MiB ciphertext limits remain.
