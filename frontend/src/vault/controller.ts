import { ApiError, accountError } from '../api.ts'
import { createEncryptedVault, createRecoveryKey, decryptEntry, encryptEntry, prepareKeyRotation, rewrapEncryptedVault,
  rewrapWithRecovery, unlockEncryptedVault } from './crypto.ts'
import type { DeriveKey } from './crypto.ts'
import { DEFAULT_PREFERENCES, validatePayload, VaultDataError } from './format.ts'
import type { EncryptedEntry, EntryPayload, RecoveryEnvelope, SecurityPreferences, UnlockedEntry, VaultMetadata } from './format.ts'
import { sameWrapper } from './api.ts'
import type { VaultApi } from './api.ts'
import { BackupError, createBackup, openBackup } from './backup.ts'
import type { OpenedBackup } from './backup.ts'
import type { RestoreEnvelope } from './api.ts'
import { OutboxError, pendingWriteId } from './outbox.ts'
import type { Outbox, PendingWrite, TrashAction } from './outbox.ts'

type EntrySnapshot = { entries: UnlockedEntry[]; trash: UnlockedEntry[]; entriesVersion: string | null }
type EncryptedSnapshot = { envelopes: EncryptedEntry[]; entriesVersion: string | null }
type PendingChange = { write: PendingWrite; data: EntryPayload | null; status: 'waiting' | 'conflict' | 'blocked' | 'unavailable' }
type Snapshot = { ownerId: number | null; loaded: boolean; busy: boolean; unlocked: boolean; error: string;
  offlineReady: boolean; offlineUnlocked: boolean;
  vaults: VaultMetadata[]; selectedId: string | null; entries: UnlockedEntry[]; trash: UnlockedEntry[]; preferences: SecurityPreferences; lockEpoch: number;
  backupExport: { text: string; fileName: string } | null;
  backupPreview: { exportedAt: string; count: number; titles: string[]; alreadyRestored: boolean } | null;
  backupResult: string; masterPasswordResult: string; keyRotationResult: string; recoveryResult: string;
  recoveryCode: string | null; entriesVersion: string | null; pending: PendingChange[]; pendingError: string }
type Operation = { signal: AbortSignal }
type RunOptions = { work?: 'backup' | 'recovery'; allowOffline?: boolean }
const initial = (): Snapshot => ({ ownerId: null, loaded: false, busy: false, unlocked: false, error: '',
  offlineReady: false, offlineUnlocked: false,
  vaults: [], selectedId: null, entries: [], trash: [], preferences: { ...DEFAULT_PREFERENCES }, lockEpoch: 0,
  backupExport: null, backupPreview: null, backupResult: '', masterPasswordResult: '', keyRotationResult: '',
  recoveryCode: null, recoveryResult: '', entriesVersion: null, pending: [], pendingError: '' })

function networkUnavailable(error: unknown) {
  return error instanceof TypeError || (error instanceof DOMException && error.name === 'TimeoutError')
}

function canRetry(error: unknown) {
  return networkUnavailable(error) ||
    (error instanceof ApiError && (error.status === 429 || error.status >= 500 || error.status === 200 || error.status === 201))
}

function accessLost(error: unknown) {
  return error instanceof ApiError && ([401, 403].includes(error.status) || error.code === 'vault_key_changed')
}

function sameContent(left: EncryptedEntry, right: EncryptedEntry) {
  return left.revision === right.revision && left.nonce === right.nonce && left.ciphertext === right.ciphertext
}

function matchesWrite(remote: EncryptedEntry | undefined, { kind, envelope }: PendingWrite) {
  return remote && sameContent(remote, envelope) && (!kind ||
    (remote.state_version === envelope.state_version + 1 && (remote.deleted_at !== null) === (kind === 'move')))
}

function hasConflict(remote: EncryptedEntry | undefined, { kind, envelope: pending }: PendingWrite) {
  if (kind) return !remote || !sameContent(remote, pending) || remote.state_version !== pending.state_version ||
    (remote.deleted_at !== null) !== (kind === 'restore')
  if (pending.revision === 1) return remote !== undefined
  return !remote || remote.deleted_at !== null || remote.revision !== pending.revision - 1 || remote.state_version !== pending.state_version
}

function applyEntry(snapshot: EntrySnapshot, envelope: EncryptedEntry, data: EntryPayload): EntrySnapshot {
  const entries = snapshot.entries.filter((item) => item.envelope.id !== envelope.id)
  const trash = snapshot.trash.filter((item) => item.envelope.id !== envelope.id)
  const target = envelope.deleted_at === null ? entries : trash
  target.unshift({ envelope, data })
  return { entries, trash, entriesVersion: null }
}

export class VaultController {
  #state: Snapshot = initial()
  #key: CryptoKey | null = null
  #epoch = 0
  #abort: AbortController | null = null
  #syncAbort: AbortController | null = null
  #listeners = new Set<() => void>()
  #lastActivity = 0
  #api: VaultApi
  #derive: DeriveKey
  #clock: () => number
  #outbox?: Outbox
  #offlineCache: { vault: VaultMetadata; snapshot: EncryptedSnapshot } | null = null
  #backupDraft: OpenedBackup | null = null
  #backupWork = false
  #recoveryDraft: { previous: VaultMetadata; recovery: RecoveryEnvelope } | null = null
  #recoveryWork = false

  constructor(api: VaultApi, derive: DeriveKey, clock = Date.now, outbox?: Outbox) {
    this.#api = api; this.#derive = derive; this.#clock = clock; this.#outbox = outbox
  }
  getSnapshot = () => this.#state
  subscribe = (listener: () => void) => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener) } }
  #publish(patch: Partial<Snapshot>) {
    const next = { ...this.#state, ...patch }
    if (next.unlocked && !next.offlineUnlocked && (patch.entries || patch.trash)) {
      const vault = next.vaults.find((item) => item.id === next.selectedId)
      if (vault) this.#offlineCache = { vault, snapshot: { entriesVersion: next.entriesVersion,
        envelopes: [...next.entries, ...next.trash].map(({ envelope }) => envelope) } }
    }
    next.offlineReady = next.loaded && this.#offlineCache?.vault.id === next.selectedId
    this.#state = next
    this.#listeners.forEach((listener) => listener())
  }
  #selectedVault() { return this.#state.vaults.find((vault) => vault.id === this.#state.selectedId) }

  lock = () => {
    this.#epoch += 1
    this.#abort?.abort()
    this.#syncAbort?.abort()
    this.#syncAbort = null
    this.#key = null
    this.#backupDraft = null
    this.#backupWork = false
    this.#recoveryDraft = null
    this.#recoveryWork = false
    this.#publish({ entries: [], trash: [], unlocked: false, offlineUnlocked: false, busy: false, error: '', lockEpoch: this.#state.lockEpoch + 1,
      backupExport: null, backupPreview: null, backupResult: '', masterPasswordResult: '', keyRotationResult: '',
      recoveryCode: null, recoveryResult: '', entriesVersion: null, pending: [], pendingError: '' })
  }

  forgetOffline = () => {
    this.#offlineCache = null
    this.lock()
  }

  switchAccount(ownerId: number | null, enabled: boolean) {
    this.forgetOffline()
    this.#state = { ...initial(), ownerId, lockEpoch: this.#state.lockEpoch }
    this.#publish({})
    if (ownerId !== null && enabled) void this.load()
  }

  async #run(action: (op: Operation) => Promise<{ patch: Partial<Snapshot>; key?: CryptoKey; backupDraft?: OpenedBackup | null; lock?: boolean }>, options: RunOptions = {}): Promise<boolean> {
    if (this.#state.busy || this.#state.ownerId === null) return false
    if (this.#state.offlineUnlocked && !options.allowOffline) {
      this.#publish({ error: 'Reconnect and sync before using this action.' })
      return false
    }
    this.#syncAbort?.abort()
    this.#syncAbort = null
    const epoch = ++this.#epoch
    const abort = new AbortController()
    this.#abort = abort
    this.#backupWork = options.work === 'backup'
    this.#recoveryWork = options.work === 'recovery'
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
      if (accessLost(error)) this.forgetOffline()
      else if (!(error instanceof BackupError || error instanceof OutboxError || (this.#outbox && canRetry(error))) &&
          !(error instanceof ApiError)) this.lock()
      this.#publish({ busy: false, error: error instanceof VaultDataError || error instanceof BackupError ||
        error instanceof OutboxError ? error.message : accountError(error) })
      return false
    } finally {
      if (epoch === this.#epoch) { this.#backupWork = false; this.#recoveryWork = false }
    }
  }

  async #fetchVaults(signal: AbortSignal) {
    let vaults: VaultMetadata[]
    try { vaults = await this.#api.vaults(signal) }
    catch (error) {
      signal.throwIfAborted()
      if (error instanceof VaultDataError) this.#offlineCache = null
      if (error instanceof ApiError && error.status === 404) {
        this.#offlineCache = null
        throw new VaultDataError('The vault list is no longer available.')
      }
      throw error
    }
    signal.throwIfAborted()
    const cached = this.#offlineCache?.vault
    if (cached && !vaults.some((vault) => sameWrapper(vault, cached))) this.#offlineCache = null
    return vaults
  }

  load = () => {
    this.lock()
    return this.#run(async ({ signal }) => {
      const [vaults, preferences] = await Promise.all([this.#fetchVaults(signal), this.#api.preferences(signal)])
      return { patch: { vaults, preferences, loaded: true, selectedId: vaults.find((vault) => vault.id === this.#state.selectedId)?.id ?? vaults[0]?.id ?? null } }
    })
  }

  select(id: string) {
    if (!this.#state.vaults.some((vault) => vault.id === id)) return
    this.forgetOffline()
    this.#publish({ selectedId: id })
  }

  create = (master: string) => this.#run(async ({ signal }) => {
    if (!this.#state.loaded) throw new VaultDataError('Refresh your vault list before creating a vault.')
    if (this.#state.unlocked || this.#state.vaults.length >= 10) throw new ApiError('Lock your vault first. Each account can have up to ten vaults.', 400)
    const previous = this.#state.vaults
    const { vault, key } = await createEncryptedVault(master, this.#derive, signal)
    signal.throwIfAborted()
    let saved: VaultMetadata
    try { saved = await this.#api.create(vault, signal) }
    catch (error) { if (!signal.aborted) this.#publish({ loaded: false }); throw error }
    return { key, patch: { vaults: [...previous, saved], selectedId: saved.id, unlocked: true, entries: [], trash: [], loaded: true } }
  })

  async #readEnvelopes(id: string, signal: AbortSignal, keyVersion: number): Promise<EncryptedSnapshot> {
    let entriesVersion: string | null = null
    try {
      const envelopes = await this.#api.entries(id, signal, (version) => { entriesVersion = version }, keyVersion)
      return { envelopes, entriesVersion }
    } catch (error) {
      signal.throwIfAborted()
      if (error instanceof VaultDataError || (error instanceof ApiError && error.status === 404)) this.#offlineCache = null
      if (error instanceof ApiError && error.status === 404) throw new VaultDataError('This vault is no longer available.')
      throw error
    }
  }

  async #decryptSnapshot(key: CryptoKey, { envelopes, entriesVersion }: EncryptedSnapshot, signal: AbortSignal): Promise<EntrySnapshot> {
    const entries: UnlockedEntry[] = []
    try {
      for (const envelope of envelopes) {
        signal.throwIfAborted()
        entries.push({ envelope, data: await decryptEntry(key, envelope) })
      }
    } catch (error) {
      signal.throwIfAborted()
      this.#offlineCache = null
      throw error
    }
    return { entriesVersion, entries: entries.filter((entry) => entry.envelope.deleted_at === null),
      trash: entries.filter((entry) => entry.envelope.deleted_at !== null) }
  }

  async #readEntries(key: CryptoKey, id: string, signal: AbortSignal, keyVersion = this.#selectedVault()?.key_version ?? 1) {
    return this.#decryptSnapshot(key, await this.#readEnvelopes(id, signal, keyVersion), signal)
  }

  async #readPending(key: CryptoKey, vaultId: string, keyVersion: number, signal: AbortSignal) {
    const ownerId = this.#state.ownerId!
    const pending: PendingChange[] = []
    try {
      const rows = await this.#outbox?.list(ownerId, vaultId) ?? []
      for (const write of rows) {
        signal.throwIfAborted()
        let data: EntryPayload | null = null
        if (write.keyVersion === keyVersion) {
          try { data = await decryptEntry(key, write.envelope) } catch (error) { if (!(error instanceof VaultDataError)) throw error }
        }
        const previous = this.#state.pending.find((item) => pendingWriteId(item.write) === pendingWriteId(write))
        pending.push({ write, data, status: data ? previous?.status ?? 'waiting' : 'unavailable' })
      }
      return { pending, pendingError: '' }
    } catch (error) {
      signal.throwIfAborted()
      if (!(error instanceof OutboxError)) throw error
      return { pending: this.#state.pending, pendingError: error.message }
    }
  }

  #sendWrite(write: PendingWrite, signal: AbortSignal) {
    const entry = write.envelope
    if (write.kind === 'move') return this.#api.remove(entry, signal, write.keyVersion)
    if (write.kind === 'restore') return this.#api.restoreEntry(entry, signal, write.keyVersion)
    return this.#api.save(entry.vault_id, entry.id, entry.revision, entry, signal, entry.state_version, write.keyVersion)
  }

  async #confirmWrite(write: PendingWrite, signal: AbortSignal) {
    const { vault_id: vaultId, id } = write.envelope
    const current = await this.#api.entry(vaultId, id, signal)
    return current && matchesWrite(current, write) ? current : null
  }

  async #replay(snapshot: EntrySnapshot, drafts: PendingChange[], signal: AbortSignal, retryBlocked = false) {
    const pending: PendingChange[] = []
    const remote = new Map([...snapshot.entries, ...snapshot.trash].map((item) => [item.envelope.id, item.envelope]))
    const ownerId = this.#state.ownerId!
    let retryLater = false
    let trashChanged = false
    for (const draft of drafts) {
      signal.throwIfAborted()
      const { write, data } = draft
      const entry = write.envelope
      const current = remote.get(entry.id)
      if (!data) { pending.push(draft); continue }
      if (matchesWrite(current, write)) {
        await this.#outbox!.change(ownerId, entry.vault_id, write, null)
        if (write.kind) trashChanged = true
        continue
      }
      if (hasConflict(current, write)) { pending.push({ ...draft, status: 'conflict' }); continue }
      if (retryLater || (draft.status === 'blocked' && !retryBlocked)) { pending.push(draft); continue }
      let envelope: EncryptedEntry | null
      try {
        envelope = await this.#sendWrite(write, signal)
      } catch (error) {
        signal.throwIfAborted()
        if (canRetry(error)) { retryLater = true; pending.push({ ...draft, status: 'waiting' }); continue }
        if (!(error instanceof ApiError) || error.code === 'vault_key_changed') throw error
        if (error.status === 400 || error.status === 413) { pending.push({ ...draft, status: 'blocked' }); continue }
        if (error.status !== 409 && error.status !== 404) throw error
        snapshot.entriesVersion = null
        try { envelope = await this.#confirmWrite(write, signal) }
        catch (lookupError) {
          signal.throwIfAborted()
          if (!canRetry(lookupError)) throw lookupError
          retryLater = true
          pending.push({ ...draft, status: 'waiting' })
          continue
        }
      }
      if (!envelope) { pending.push({ ...draft, status: 'conflict' }); continue }
      signal.throwIfAborted()
      await this.#outbox!.change(ownerId, entry.vault_id, write, null)
      snapshot = applyEntry(snapshot, envelope, data)
      if (write.kind) trashChanged = true
    }
    return { ...snapshot, pending, ...(trashChanged ? { backupExport: null } : {}) }
  }

  async #stageWrite(write: PendingWrite, data: EntryPayload, signal: AbortSignal): Promise<{ patch: Partial<Snapshot> }> {
    const outbox = this.#outbox
    const ownerId = this.#state.ownerId!
    const { vault_id: vaultId, id } = write.envelope
    const apply = (envelope: EncryptedEntry) => ({ ...applyEntry(this.#state, envelope, data), ...(write.kind ? { backupExport: null } : {}) })
    let journaled: boolean | undefined
    try { journaled = await outbox?.change(ownerId, vaultId, null, write) }
    catch (error) {
      if (!(error instanceof OutboxError && error.unavailable) || this.#state.offlineUnlocked) throw error
    }
    signal.throwIfAborted()
    if (!outbox || journaled === undefined) {
      if (this.#state.offlineUnlocked) throw new OutboxError()
      try { return { patch: apply(await this.#sendWrite(write, signal)) } }
      catch (error) {
        if (outbox && canRetry(error)) throw new OutboxError('The server is unreachable and this browser could not store the change.')
        throw error
      }
    }
    if (!journaled) throw new OutboxError('This entry already has a local change. Sync or discard it before changing the entry again.')
    const change: PendingChange = { write, data, status: 'waiting' }
    const otherChanges = this.#state.pending.filter((item) => item.write.envelope.id !== id)
    this.#publish({ pending: [...otherChanges, change], pendingError: '' })
    if (this.#state.offlineUnlocked) return { patch: {} }
    try {
      const envelope = await this.#sendWrite(write, signal)
      signal.throwIfAborted()
      await outbox.change(ownerId, vaultId, write, null)
      return { patch: { ...apply(envelope), pending: otherChanges } }
    } catch (error) {
      if (canRetry(error)) return { patch: {} }
      if (error instanceof ApiError && error.code !== 'vault_key_changed') {
        if (error.status === 409 || error.status === 404) return { patch: { entriesVersion: null } }
        if (error.status === 400 || error.status === 413) return { patch: { pending: [...otherChanges, { ...change, status: 'blocked' }] } }
      }
      throw error
    }
  }

  unlock = (master: string) => this.#run(async ({ signal }) => {
    const selectedId = this.#state.selectedId
    if (!this.#state.loaded || !selectedId) throw new VaultDataError('Load and select your vault first.')
    // A different device may have changed the password since this client locked.
    let vaults = this.#state.vaults
    let cachedSnapshot: EncryptedSnapshot | undefined
    const useCached = (error: unknown) => {
      signal.throwIfAborted()
      const cached = this.#offlineCache
      if (!networkUnavailable(error) || cached?.vault.id !== selectedId) throw error
      cachedSnapshot = cached.snapshot
      return cached
    }
    let metadata: VaultMetadata | undefined
    try {
      vaults = await this.#fetchVaults(signal)
      metadata = vaults.find((vault) => vault.id === selectedId)
    } catch (error) { metadata = useCached(error).vault }
    if (!metadata) throw new VaultDataError('Load and select your vault first.')
    const key = await unlockEncryptedVault(metadata, master, this.#derive, signal)
    const keyVersion = metadata.key_version ?? 1
    signal.throwIfAborted()
    const encrypted = cachedSnapshot ?? await this.#readEnvelopes(metadata.id, signal, keyVersion).catch((error) => useCached(error).snapshot)
    const snapshot = await this.#decryptSnapshot(key, encrypted, signal)
    const drafts = await this.#readPending(key, metadata.id, keyVersion, signal)
    return { key, patch: { ...snapshot, ...drafts, vaults, unlocked: true, offlineUnlocked: cachedSnapshot !== undefined,
      masterPasswordResult: '', keyRotationResult: '', recoveryResult: '' } }
  })

  async #revalidateOffline(signal: AbortSignal): Promise<Partial<Snapshot>> {
    if (!this.#state.offlineUnlocked) return {}
    const vaults = await this.#fetchVaults(signal)
    if (!this.#offlineCache) throw new VaultDataError('Vault access or its master password changed. Unlock again while connected.')
    return { vaults, offlineUnlocked: false, error: '' }
  }

  async #readWithLocalFallback<T>(read: () => Promise<T>, key: CryptoKey, vaultId: string, keyVersion: number, signal: AbortSignal) {
    try { return await read() }
    catch (error) {
      signal.throwIfAborted()
      if (networkUnavailable(error)) {
        const drafts = await this.#readPending(key, vaultId, keyVersion, signal)
        signal.throwIfAborted()
        this.#publish(drafts)
      }
      throw error
    }
  }

  refresh = () => this.#run(async ({ signal }) => {
    const key = this.#key
    const id = this.#state.selectedId
    if (!key || !id) throw new VaultDataError('Unlock your vault first.')
    const keyVersion = this.#selectedVault()?.key_version ?? 1
    const { connection, snapshot } = await this.#readWithLocalFallback(async () => {
      const connection = await this.#revalidateOffline(signal)
      signal.throwIfAborted()
      return { connection, snapshot: await this.#readEntries(key, id, signal, keyVersion) }
    }, key, id, keyVersion, signal)
    signal.throwIfAborted()
    const drafts = await this.#readPending(key, id, keyVersion, signal)
    return { patch: drafts.pendingError ? { ...snapshot, ...drafts, ...connection } :
      { ...await this.#replay(snapshot, drafts.pending, signal, true), pendingError: '', ...connection } }
  }, { allowOffline: true })

  sync = async () => {
    const { unlocked, selectedId, busy, entriesVersion } = this.#state
    const key = this.#key
    if ((!key && !this.#offlineCache) || !selectedId || busy || this.#syncAbort) return
    const controller = new AbortController()
    this.#syncAbort = controller
    const { signal } = controller
    const current = () => this.#syncAbort === controller && !signal.aborted
    try {
      if (!unlocked || !key) {
        const vaults = await this.#fetchVaults(signal)
        if (current() && !this.#offlineCache) this.#publish({ vaults, selectedId: vaults.find((vault) => vault.id === selectedId)?.id ?? vaults[0]?.id ?? null })
        return
      }
      const keyVersion = this.#selectedVault()?.key_version ?? 1
      const { connection, remote, snapshot } = await this.#readWithLocalFallback(async () => {
        const connection = await this.#revalidateOffline(signal)
        signal.throwIfAborted()
        const remote = await this.#api.entriesVersion(selectedId, signal, keyVersion)
        signal.throwIfAborted()
        const snapshot = remote === entriesVersion
          ? { entries: this.#state.entries, trash: this.#state.trash, entriesVersion }
          : await this.#readEntries(key, selectedId, signal, keyVersion)
        return { connection, remote, snapshot }
      }, key, selectedId, keyVersion, signal)
      if (!current()) return
      const drafts = await this.#readPending(key, selectedId, keyVersion, signal)
      if (!current()) return
      if (remote === entriesVersion && !drafts.pending.length) {
        if (connection.vaults || this.#state.pending.length || this.#state.pendingError !== drafts.pendingError) this.#publish({ ...drafts, ...connection })
        return
      }
      const patch = drafts.pendingError ? { ...snapshot, ...drafts } :
        { ...await this.#replay(snapshot, drafts.pending, signal), pendingError: '' }
      if (current()) this.#publish({ ...patch, ...connection })
    } catch (error) {
      const lostAccess = accessLost(error) || (error instanceof ApiError && error.status === 404 && Boolean(this.#offlineCache || this.#outbox || entriesVersion))
      if (current() && (error instanceof VaultDataError || lostAccess)) {
        this.forgetOffline()
        this.#publish({ error: error instanceof VaultDataError ? error.message : accountError(error) })
      } else if (current() && error instanceof OutboxError) {
        this.#publish({ pendingError: error.message })
      }
    } finally {
      if (this.#syncAbort === controller) this.#syncAbort = null
    }
  }

  save = (value: EntryPayload, existingId?: string, expectedRevision?: number, expectedStateVersion?: number) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new VaultDataError('Unlock your vault first.')
    const data = validatePayload(value)
    const existing = existingId ? this.#state.entries.find((entry) => entry.envelope.id === existingId) : undefined
    if (existingId && !existing) throw new ApiError('This entry is no longer active. You can save your edits as a new copy.', 409)
    if (existing && expectedRevision !== existing.envelope.revision) throw new ApiError('Entry changed. Close the editor and refresh before saving.', 409)
    if (existing && expectedStateVersion !== existing.envelope.state_version) throw new ApiError('Entry moved to or from Trash. Close the editor and refresh before saving.', 409)
    const id = existingId ?? crypto.randomUUID()
    const revision = existing ? existing.envelope.revision + 1 : 1
    const encrypted = await encryptEntry(this.#key, this.#state.selectedId, id, revision, data)
    signal.throwIfAborted()
    const now = new Date(this.#clock()).toISOString()
    return this.#stageWrite({ keyVersion: this.#selectedVault()?.key_version ?? 1, envelope: { id, vault_id: this.#state.selectedId, revision,
      state_version: existing?.envelope.state_version ?? 1, deleted_at: null, created_at: existing?.envelope.created_at ?? now,
      updated_at: now, ...encrypted } }, data, signal)
  }, { allowOffline: true })

  resolvePending = (operationId: string, asCopy: boolean) => this.#run(async ({ signal }) => {
    const draft = this.#state.pending.find((item) => pendingWriteId(item.write) === operationId)
    const key = this.#key
    const vaultId = this.#state.selectedId
    if (!draft || !this.#outbox || !key || !vaultId) throw new OutboxError('Unlock and refresh your local changes first.')
    let replacement: PendingChange | null = null
    if (asCopy) {
      if (draft.write.kind || !draft.data || draft.status !== 'conflict') throw new OutboxError('Only readable entry drafts with a conflict can be saved as copies.')
      const id = crypto.randomUUID()
      const now = new Date(this.#clock()).toISOString()
      const encrypted = await encryptEntry(key, vaultId, id, 1, draft.data)
      replacement = { data: draft.data, status: 'waiting', write: { keyVersion: draft.write.keyVersion, envelope: {
        id, vault_id: vaultId, revision: 1, state_version: 1, created_at: now, updated_at: now, deleted_at: null, ...encrypted } } }
    }
    signal.throwIfAborted()
    if (!await this.#outbox.change(this.#state.ownerId!, vaultId, draft.write, replacement?.write ?? null)) {
      throw new OutboxError('The local change was updated in another tab. Refresh the vault and try again.')
    }
    const pending = this.#state.pending.filter((item) => item !== draft)
    if (replacement) pending.push(replacement)
    return { patch: { pending, pendingError: '' } }
  }, { allowOffline: true })

  #changeTrash(kind: TrashAction, id: string, expectedRevision: number, expectedStateVersion: number) {
    return this.#run(async ({ signal }) => {
      if (!this.#key) throw new VaultDataError('Unlock and refresh the vault before changing Trash.')
      const records = kind === 'move' ? this.#state.entries : this.#state.trash
      const entry = records.find((item) => item.envelope.id === id)
      if (!entry || expectedRevision !== entry.envelope.revision || expectedStateVersion !== entry.envelope.state_version) {
        throw new ApiError('This entry changed. Refresh before changing its Trash status.', 409)
      }
      if (expectedStateVersion >= 2147483647) throw new ApiError('This entry has reached the Trash version limit.', 409)
      return this.#stageWrite({ kind, operationId: crypto.randomUUID(), envelope: entry.envelope,
        keyVersion: this.#selectedVault()?.key_version ?? 1 }, entry.data, signal)
    }, { allowOffline: true })
  }

  remove = (id: string, expectedRevision: number, expectedStateVersion: number) =>
    this.#changeTrash('move', id, expectedRevision, expectedStateVersion)

  restoreEntry = (id: string, expectedRevision: number, expectedStateVersion: number) =>
    this.#changeTrash('restore', id, expectedRevision, expectedStateVersion)

  purge = (id: string, expectedRevision: number, expectedStateVersion: number) => this.#run(async ({ signal }) => {
    const entry = this.#state.trash.find((item) => item.envelope.id === id)
    if (!this.#key || !entry) throw new VaultDataError('Unlock and refresh before permanently deleting.')
    if (expectedRevision !== entry.envelope.revision || expectedStateVersion !== entry.envelope.state_version) throw new ApiError('Entry changed. Refresh Trash before permanently deleting.', 409)
    const pending = await this.#outbox?.list(this.#state.ownerId!, entry.envelope.vault_id).catch((error) => {
      if (error instanceof OutboxError && error.unavailable) return []
      throw error
    })
    signal.throwIfAborted()
    if (pending?.some((write) => write.envelope.id === id)) throw new OutboxError('Sync or discard this entry’s local change before permanently deleting it.')
    await this.#api.purge(entry.envelope, signal, this.#selectedVault()?.key_version)
    return { patch: { trash: this.#state.trash.filter((item) => item.envelope.id !== id), backupExport: null } }
  })

  updatePreferences = (value: SecurityPreferences) => this.#run(async ({ signal }) => ({ patch: { preferences: await this.#api.updatePreferences(value, signal) } }))

  changeMasterPassword = (currentMaster: string, newMaster: string) => this.#run(async ({ signal }) => {
    const previous = this.#selectedVault()
    if (!this.#key || !this.#state.unlocked || !previous) throw new VaultDataError('Unlock your vault before changing its master password.')
    const vaults = this.#state.vaults
    const { vault, key } = await rewrapEncryptedVault(previous, currentMaster, newMaster, this.#derive, signal)
    // Authenticate active and trashed entries under the preserved data key before committing.
    await this.#readEntries(key, previous.id, signal)
    signal.throwIfAborted()
    // A lock or lost response after dispatch must require fresh metadata as well.
    this.#offlineCache = null
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

  rotateKey = (currentMaster: string, newMaster: string) => this.#run(async ({ signal }) => {
    const previous = this.#selectedVault()
    if (!this.#key || !this.#state.unlocked || !previous) throw new VaultDataError('Unlock your vault before rotating its encryption key.')
    if ((await this.#outbox?.list(this.#state.ownerId!, previous.id))?.length) {
      throw new OutboxError('Sync or discard this device’s local changes before rotating the vault encryption key.')
    }
    const vaults = this.#state.vaults
    const { envelopes, entriesVersion } = await this.#readEnvelopes(previous.id, signal, previous.key_version ?? 1)
    if (!entriesVersion) throw new VaultDataError('A current vault snapshot is required to rotate its encryption key.')
    const { vault, entries } = await prepareKeyRotation(previous, envelopes, currentMaster, newMaster, this.#derive, signal)
    signal.throwIfAborted()
    // A cancellation or lost response after dispatch cannot safely reuse the old wrapper.
    this.#offlineCache = null
    this.#publish({ loaded: false, vaults: [] })
    let saved: VaultMetadata
    try { saved = await this.#api.rotateKey(previous, vault, entriesVersion, entries, signal) }
    catch (error) {
      if (!signal.aborted) {
        this.lock()
        this.#publish({ error: error instanceof ApiError && error.status === 409
          ? 'The vault changed during rotation. Reload the vault list and unlock before trying again.'
          : 'Rotation could not be confirmed. Reload the vault list and try the new master password first. If it does not work, try the previous one.' })
      }
      return { patch: {} }
    }
    return { lock: true, patch: { loaded: true, vaults: vaults.map((item) => item.id === saved.id ? saved : item),
      keyRotationResult: 'Vault encryption key rotated. Unlock your vault with the new master password.' } }
  })

  async #currentVault(signal: AbortSignal) {
    const selected = this.#selectedVault()
    if (!selected || !this.#state.loaded) throw new VaultDataError('Load and select your vault first.')
    const vaults = await this.#fetchVaults(signal)
    const previous = vaults.find((vault) => vault.id === selected.id)
    if (!previous) throw new VaultDataError('This vault is no longer available.')
    if (this.#state.unlocked && previous.key_version !== selected.key_version) {
      throw new VaultDataError('The vault encryption key changed. Unlock the vault again.')
    }
    return { previous, vaults }
  }

  prepareRecovery = (master: string) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked) throw new VaultDataError('Unlock the vault before setting up a recovery key.')
    this.#recoveryDraft = null
    this.#publish({ recoveryCode: null, recoveryResult: '' })
    const { previous, vaults } = await this.#currentVault(signal)
    const { code, recovery } = await createRecoveryKey(previous, master, this.#derive, signal)
    signal.throwIfAborted()
    this.#recoveryDraft = { previous, recovery }
    return { patch: { vaults, recoveryCode: code } }
  }, { work: 'recovery' })

  cancelRecoveryDraft = () => {
    this.#recoveryDraft = null
    if (this.#recoveryWork) {
      this.#epoch += 1
      this.#abort?.abort()
      this.#recoveryWork = false
      this.#publish({ busy: false, recoveryCode: null })
    } else if (this.#state.recoveryCode !== null) this.#publish({ recoveryCode: null })
  }

  async #saveRecovery(previous: VaultMetadata, recovery: RecoveryEnvelope | null, signal: AbortSignal) {
    try { return await this.#api.setupRecovery(previous, recovery, signal) }
    catch (error) {
      if (!signal.aborted) {
        this.lock()
        this.#publish({ loaded: false, vaults: [], error: error instanceof ApiError && error.status === 409
          ? 'Vault recovery settings changed. Reload the vault list before trying again.'
          : 'The recovery change could not be confirmed. Reload the vault list to check which key is active.' })
      }
      return null
    }
  }

  confirmRecovery = () => this.#run(async ({ signal }) => {
    const draft = this.#recoveryDraft
    if (!this.#key || !draft || draft.previous.id !== this.#state.selectedId) throw new VaultDataError('Generate and save a recovery key first.')
    this.#recoveryDraft = null
    this.#publish({ recoveryCode: null })
    const saved = await this.#saveRecovery(draft.previous, draft.recovery, signal)
    return { patch: saved ? { vaults: this.#state.vaults.map((item) => item.id === saved.id ? saved : item),
      recoveryResult: 'Your new recovery key is active.' } : {} }
  })

  disableRecovery = (master: string) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked) throw new VaultDataError('Unlock the vault before disabling its recovery key.')
    const { previous, vaults } = await this.#currentVault(signal)
    if (!previous.recovery) return { patch: { vaults, recoveryResult: 'No recovery key is active.' } }
    await unlockEncryptedVault(previous, master, this.#derive, signal)
    signal.throwIfAborted()
    const saved = await this.#saveRecovery(previous, null, signal)
    return { patch: saved ? { vaults: vaults.map((item) => item.id === saved.id ? saved : item),
      recoveryResult: 'Vault recovery key disabled.' } : {} }
  })

  recoverWithKey = (code: string, newMaster: string) => this.#run(async ({ signal }) => {
    if (this.#state.unlocked) throw new VaultDataError('Lock the vault before using a recovery key.')
    const { previous, vaults } = await this.#currentVault(signal)
    const { vault, key } = await rewrapWithRecovery(previous, code, newMaster, this.#derive, signal)
    // Check both active and trashed ciphertext before committing the new master wrapper.
    await this.#readEntries(key, previous.id, signal, previous.key_version ?? 1)
    signal.throwIfAborted()
    this.#offlineCache = null
    this.#publish({ loaded: false, vaults: [] })
    let saved: VaultMetadata
    try { saved = await this.#api.recoverVault(previous, vault, signal) }
    catch (error) {
      if (!signal.aborted) {
        this.lock()
        this.#publish({ error: error instanceof ApiError && error.status === 409
          ? 'Vault recovery settings changed. Reload the vault list before trying again.'
          : 'Recovery could not be confirmed. Reload the vault list and try the new master password first.' })
      }
      return { patch: {} }
    }
    return { lock: true, patch: { loaded: true, vaults: vaults.map((item) => item.id === saved.id ? saved : item),
      recoveryResult: 'Master password reset. Unlock with the new password, then set up a new recovery key.' } }
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
  }, { work: 'backup' })

  prepareRestore = (text: string, password: string) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new BackupError('Unlock the destination vault before restoring.')
    this.#backupDraft = null
    this.#publish({ backupPreview: null, backupResult: '' })
    const draft = await openBackup(text, password, this.#derive, signal)
    const receipt = await this.#api.restoreReceipt(this.#state.selectedId, draft.backupId, signal)
    if (receipt && (receipt.archive_digest !== draft.archiveDigest || receipt.entry_count !== draft.content.entries.length)) throw new BackupError('Backup identity conflicts with an earlier restore.')
    return { backupDraft: draft, patch: { backupPreview: { exportedAt: draft.content.exported_at, count: draft.content.entries.length,
      titles: draft.content.entries.slice(0, 10).map((entry) => entry.payload.title), alreadyRestored: Boolean(receipt) } } }
  }, { work: 'backup' })

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
      repeated = (await this.#api.restore(vaultId, draft.backupId, draft.archiveDigest, entries, signal,
        this.#selectedVault()?.key_version)).already_restored
    }
    const snapshot = await this.#readEntries(key, vaultId, signal)
    return { backupDraft: null, patch: { ...snapshot, backupPreview: null,
      backupResult: repeated ? 'This backup was already restored. No duplicate entries were added.' : `Restored ${draft.content.entries.length} entries. Existing entries were preserved.` } }
  }, { work: 'backup' })

  checkIdle = () => {
    const elapsed = this.#clock() - this.#lastActivity
    if (this.#state.unlocked && (elapsed < 0 || elapsed >= this.#state.preferences.auto_lock_seconds * 1000)) this.lock()
  }
  touch = () => { this.checkIdle(); if (this.#state.unlocked) this.#lastActivity = this.#clock() }
  hidden = () => { if (this.#state.preferences.lock_on_hidden) this.lock(); else this.cancelRecoveryDraft() }
}
