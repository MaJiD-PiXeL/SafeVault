import { ApiError, accountError } from '../api.ts'
import { createEncryptedVault, decryptEntry, encryptEntry, rewrapEncryptedVault, unlockEncryptedVault } from './crypto.ts'
import type { DeriveKey } from './crypto.ts'
import { DEFAULT_PREFERENCES, validatePayload, VaultDataError } from './format.ts'
import type { EntryPayload, SecurityPreferences, UnlockedEntry, VaultMetadata } from './format.ts'
import type { VaultApi } from './api.ts'
import { BackupError, createBackup, openBackup } from './backup.ts'
import type { OpenedBackup } from './backup.ts'
import type { RestoreEnvelope } from './api.ts'

type Snapshot = { ownerId: number | null; loaded: boolean; busy: boolean; unlocked: boolean; error: string;
  vaults: VaultMetadata[]; selectedId: string | null; entries: UnlockedEntry[]; trash: UnlockedEntry[]; preferences: SecurityPreferences; lockEpoch: number;
  backupExport: { text: string; fileName: string } | null;
  backupPreview: { exportedAt: string; count: number; titles: string[]; alreadyRestored: boolean } | null;
  backupResult: string; masterPasswordResult: string }
type Operation = { signal: AbortSignal }
const initial = (): Snapshot => ({ ownerId: null, loaded: false, busy: false, unlocked: false, error: '',
  vaults: [], selectedId: null, entries: [], trash: [], preferences: { ...DEFAULT_PREFERENCES }, lockEpoch: 0,
  backupExport: null, backupPreview: null, backupResult: '', masterPasswordResult: '' })

export class VaultController {
  #state: Snapshot = initial()
  #key: CryptoKey | null = null
  #epoch = 0
  #abort: AbortController | null = null
  #listeners = new Set<() => void>()
  #lastActivity = 0
  #api: VaultApi
  #derive: DeriveKey
  #clock: () => number
  #backupDraft: OpenedBackup | null = null
  #backupWork = false

  constructor(api: VaultApi, derive: DeriveKey, clock = Date.now) { this.#api = api; this.#derive = derive; this.#clock = clock }
  getSnapshot = () => this.#state
  subscribe = (listener: () => void) => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener) } }
  #publish(patch: Partial<Snapshot>) { this.#state = { ...this.#state, ...patch }; this.#listeners.forEach((listener) => listener()) }

  lock = () => {
    this.#epoch += 1
    this.#abort?.abort()
    this.#key = null
    this.#backupDraft = null
    this.#backupWork = false
    this.#publish({ entries: [], trash: [], unlocked: false, busy: false, error: '', lockEpoch: this.#state.lockEpoch + 1,
      backupExport: null, backupPreview: null, backupResult: '', masterPasswordResult: '' })
  }

  switchAccount(ownerId: number | null, enabled: boolean) {
    this.lock()
    this.#state = { ...initial(), ownerId, lockEpoch: this.#state.lockEpoch }
    this.#publish({})
    if (ownerId !== null && enabled) void this.load()
  }

  async #run(action: (op: Operation) => Promise<{ patch: Partial<Snapshot>; key?: CryptoKey; backupDraft?: OpenedBackup | null; lock?: boolean }>, backupWork = false): Promise<boolean> {
    if (this.#state.busy || this.#state.ownerId === null) return false
    const epoch = ++this.#epoch
    const abort = new AbortController()
    this.#abort = abort
    this.#backupWork = backupWork
    this.#publish({ busy: true, error: '' })
    try {
      const result = await action({ signal: abort.signal })
      if (epoch !== this.#epoch || abort.signal.aborted) return false
      if (result.lock) this.lock()
      if (result.key) { this.#key = result.key; this.#lastActivity = this.#clock() }
      if (result.backupDraft !== undefined) this.#backupDraft = result.backupDraft
      this.#publish({ ...result.patch, busy: false })
      return true
    } catch (error) {
      if (epoch !== this.#epoch || abort.signal.aborted) return false
      if (!(error instanceof BackupError) && (error instanceof VaultDataError || !(error instanceof ApiError) || [401, 403].includes(error.status))) this.lock()
      this.#publish({ busy: false, error: error instanceof VaultDataError || error instanceof BackupError ? error.message : accountError(error) })
      return false
    } finally {
      if (epoch === this.#epoch) this.#backupWork = false
    }
  }

  load = () => {
    this.lock()
    return this.#run(async ({ signal }) => {
    const [vaults, preferences] = await Promise.all([this.#api.vaults(signal), this.#api.preferences(signal)])
    return { patch: { vaults, preferences, loaded: true, selectedId: vaults.find((vault) => vault.id === this.#state.selectedId)?.id ?? vaults[0]?.id ?? null } }
    })
  }

  select(id: string) {
    if (!this.#state.vaults.some((vault) => vault.id === id)) return
    this.lock()
    this.#publish({ selectedId: id })
  }

  create = (master: string) => this.#run(async ({ signal }) => {
    if (!this.#state.loaded || this.#state.vaults.length) throw new VaultDataError('Refresh your vault list before creating a vault.')
    const { vault, key } = await createEncryptedVault(master, this.#derive, signal)
    signal.throwIfAborted()
    let saved: VaultMetadata
    try { saved = await this.#api.create(vault, signal) }
    catch (error) { if (!signal.aborted) this.#publish({ loaded: false }); throw error }
    return { key, patch: { vaults: [saved], selectedId: saved.id, unlocked: true, entries: [], trash: [], loaded: true } }
  })

  async #readEntries(key: CryptoKey, id: string, signal: AbortSignal) {
    const envelopes = await this.#api.entries(id, signal)
    const entries: UnlockedEntry[] = []
    for (const envelope of envelopes) {
      signal.throwIfAborted()
      entries.push({ envelope, data: await decryptEntry(key, envelope) })
    }
    return { entries: entries.filter((entry) => entry.envelope.deleted_at === null),
      trash: entries.filter((entry) => entry.envelope.deleted_at !== null) }
  }

  unlock = (master: string) => this.#run(async ({ signal }) => {
    const selectedId = this.#state.selectedId
    if (!this.#state.loaded || !selectedId) throw new VaultDataError('Load and select your vault first.')
    // A different device may have changed the password since this client locked.
    const vaults = await this.#api.vaults(signal)
    signal.throwIfAborted()
    const metadata = vaults.find((vault) => vault.id === selectedId)
    if (!metadata) throw new VaultDataError('Load and select your vault first.')
    const key = await unlockEncryptedVault(metadata, master, this.#derive, signal)
    const snapshot = await this.#readEntries(key, metadata.id, signal)
    return { key, patch: { ...snapshot, vaults, unlocked: true, masterPasswordResult: '' } }
  })

  refresh = () => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.selectedId) throw new VaultDataError('Unlock your vault first.')
    return { patch: await this.#readEntries(this.#key, this.#state.selectedId, signal) }
  })

  save = (value: EntryPayload, existingId?: string, expectedRevision?: number, expectedStateVersion?: number) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new VaultDataError('Unlock your vault first.')
    const data = validatePayload(value)
    const existing = existingId ? this.#state.entries.find((entry) => entry.envelope.id === existingId) : undefined
    if (existingId && !existing) throw new VaultDataError('Refresh before editing this entry.')
    if (existing && expectedRevision !== existing.envelope.revision) throw new ApiError('Entry changed. Close the editor and refresh before saving.', 409)
    if (existing && expectedStateVersion !== existing.envelope.state_version) throw new ApiError('Entry moved to or from Trash. Close the editor and refresh before saving.', 409)
    const id = existingId ?? crypto.randomUUID()
    const revision = existing ? existing.envelope.revision + 1 : 1
    const encrypted = await encryptEntry(this.#key, this.#state.selectedId, id, revision, data)
    signal.throwIfAborted()
    const envelope = await this.#api.save(this.#state.selectedId, id, revision, encrypted, signal, existing?.envelope.state_version)
    return { patch: { entries: [{ envelope, data }, ...this.#state.entries.filter((entry) => entry.envelope.id !== id)] } }
  })

  remove = (id: string, expectedRevision: number, expectedStateVersion: number) => this.#run(async ({ signal }) => {
    const entry = this.#state.entries.find((item) => item.envelope.id === id)
    if (!this.#key || !entry) throw new VaultDataError('Unlock and refresh before deleting.')
    if (expectedRevision !== entry.envelope.revision) throw new ApiError('Entry changed. Close the editor and refresh before deleting.', 409)
    if (expectedStateVersion !== entry.envelope.state_version) throw new ApiError('Entry state changed. Close the editor and refresh before moving it to Trash.', 409)
    const envelope = await this.#api.remove(entry.envelope, signal)
    return { patch: { entries: this.#state.entries.filter((item) => item.envelope.id !== id),
      trash: [{ envelope, data: entry.data }, ...this.#state.trash], backupExport: null } }
  })

  restoreEntry = (id: string, expectedRevision: number, expectedStateVersion: number) => this.#run(async ({ signal }) => {
    const entry = this.#state.trash.find((item) => item.envelope.id === id)
    if (!this.#key || !entry) throw new VaultDataError('Unlock and refresh before restoring.')
    if (expectedRevision !== entry.envelope.revision || expectedStateVersion !== entry.envelope.state_version) throw new ApiError('Entry changed. Refresh Trash before restoring.', 409)
    const envelope = await this.#api.restoreEntry(entry.envelope, signal)
    return { patch: { entries: [{ envelope, data: entry.data }, ...this.#state.entries],
      trash: this.#state.trash.filter((item) => item.envelope.id !== id), backupExport: null } }
  })

  purge = (id: string, expectedRevision: number, expectedStateVersion: number) => this.#run(async ({ signal }) => {
    const entry = this.#state.trash.find((item) => item.envelope.id === id)
    if (!this.#key || !entry) throw new VaultDataError('Unlock and refresh before permanently deleting.')
    if (expectedRevision !== entry.envelope.revision || expectedStateVersion !== entry.envelope.state_version) throw new ApiError('Entry changed. Refresh Trash before permanently deleting.', 409)
    await this.#api.purge(entry.envelope, signal)
    return { patch: { trash: this.#state.trash.filter((item) => item.envelope.id !== id), backupExport: null } }
  })

  updatePreferences = (value: SecurityPreferences) => this.#run(async ({ signal }) => ({ patch: { preferences: await this.#api.updatePreferences(value, signal) } }))

  changeMasterPassword = (currentMaster: string, newMaster: string) => this.#run(async ({ signal }) => {
    const previous = this.#state.vaults.find((vault) => vault.id === this.#state.selectedId)
    if (!this.#key || !this.#state.unlocked || !previous) throw new VaultDataError('Unlock your vault before changing its master password.')
    const vaults = this.#state.vaults
    const { vault, key } = await rewrapEncryptedVault(previous, currentMaster, newMaster, this.#derive, signal)
    // Authenticate active and trashed entries under the preserved data key before committing.
    await this.#readEntries(key, previous.id, signal)
    signal.throwIfAborted()
    // A lock or lost response after dispatch must require fresh metadata as well.
    this.#publish({ loaded: false, vaults: [] })
    let saved: VaultMetadata
    try { saved = await this.#api.changeMasterPassword(previous, vault, signal) }
    catch {
      if (!signal.aborted) {
        this.lock()
        this.#publish({ loaded: false, vaults: [], selectedId: null,
          error: 'The password change could not be confirmed. Reload the vault list before unlocking or trying again. If the new password does not work, try the previous one.' })
      }
      // The request may have committed. Never retry with cached wrapper metadata.
      return { patch: {} }
    }
    return { lock: true, patch: { loaded: true, vaults: vaults.map((item) => item.id === saved.id ? saved : item),
      masterPasswordResult: 'Master password changed. Unlock your vault with the new password.' } }
  })

  clearBackupPreview = () => {
    if (this.#state.busy) return
    this.#backupDraft = null
    this.#publish({ backupPreview: null, backupResult: '', error: '' })
  }

  cancelBackupWork = () => {
    if (this.#backupWork) {
      this.#epoch += 1
      this.#abort?.abort()
      this.#backupWork = false
      this.#publish({ busy: false })
    }
    this.#backupDraft = null
    this.#publish({ backupPreview: null, backupExport: null, backupResult: '' })
  }

  exportBackup = (password: string) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new BackupError('Unlock the vault before exporting.')
    this.#publish({ backupExport: null, backupResult: '' })
    const snapshot = await this.#readEntries(this.#key, this.#state.selectedId, signal)
    const text = await createBackup(this.#state.selectedId, snapshot.entries, password, this.#derive, signal)
    return { patch: { ...snapshot, backupExport: { text, fileName: `nexora-safevault-backup-${new Date().toISOString().replace(/[:.]/g, '-')}.json` } } }
  }, true)

  prepareRestore = (text: string, password: string) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new BackupError('Unlock the destination vault before restoring.')
    this.#backupDraft = null
    this.#publish({ backupPreview: null, backupResult: '' })
    const draft = await openBackup(text, password, this.#derive, signal)
    const receipt = await this.#api.restoreReceipt(this.#state.selectedId, draft.backupId, signal)
    if (receipt && (receipt.archive_digest !== draft.archiveDigest || receipt.entry_count !== draft.content.entries.length)) throw new BackupError('Backup identity conflicts with an earlier restore.')
    return { backupDraft: draft, patch: { backupPreview: { exportedAt: draft.content.exported_at, count: draft.content.entries.length,
      titles: draft.content.entries.slice(0, 10).map((entry) => entry.payload.title), alreadyRestored: Boolean(receipt) } } }
  }, true)

  restoreBackup = () => this.#run(async ({ signal }) => {
    const draft = this.#backupDraft
    const key = this.#key
    const vaultId = this.#state.selectedId
    if (!draft || !key || !vaultId || !this.#state.unlocked || !draft.content.entries.length) throw new BackupError('Validate a nonempty backup first.')
    const existing = await this.#api.restoreReceipt(vaultId, draft.backupId, signal)
    let repeated = Boolean(existing)
    if (existing && (existing.archive_digest !== draft.archiveDigest || existing.entry_count !== draft.content.entries.length)) throw new BackupError('Backup identity conflicts with an earlier restore.')
    if (!existing) {
      const entries: RestoreEnvelope[] = []
      const nonces = new Set([...this.#state.entries, ...this.#state.trash].map((entry) => entry.envelope.nonce))
      for (const record of draft.content.entries) {
        signal.throwIfAborted()
        const id = crypto.randomUUID()
        const encrypted = await encryptEntry(key, vaultId, id, 1, record.payload)
        if (nonces.has(encrypted.nonce)) throw new BackupError('Random nonce collision. Validate the backup again before retrying.')
        nonces.add(encrypted.nonce)
        entries.push({ id, ...encrypted })
      }
      signal.throwIfAborted()
      repeated = (await this.#api.restore(vaultId, draft.backupId, draft.archiveDigest, entries, signal)).already_restored
    }
    const snapshot = await this.#readEntries(key, vaultId, signal)
    return { backupDraft: null, patch: { ...snapshot, backupPreview: null,
      backupResult: repeated ? 'This backup was already restored. No duplicate entries were added.' : `Restored ${draft.content.entries.length} entries. Existing entries were preserved.` } }
  }, true)

  checkIdle = () => {
    const elapsed = this.#clock() - this.#lastActivity
    if (this.#state.unlocked && (elapsed < 0 || elapsed >= this.#state.preferences.auto_lock_seconds * 1000)) this.lock()
  }
  touch = () => { this.checkIdle(); if (this.#state.unlocked) this.#lastActivity = this.#clock() }
  hidden = () => { if (this.#state.preferences.lock_on_hidden) this.lock() }
}
