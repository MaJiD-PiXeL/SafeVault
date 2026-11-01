import { ApiError, accountError } from '../api.ts'
import { createEncryptedVault, decryptEntry, encryptEntry, unlockEncryptedVault } from './crypto.ts'
import type { DeriveKey } from './crypto.ts'
import { DEFAULT_PREFERENCES, validatePayload, VaultDataError } from './format.ts'
import type { EntryPayload, SecurityPreferences, UnlockedEntry, VaultMetadata } from './format.ts'
import type { VaultApi } from './api.ts'

type Snapshot = { ownerId: number | null; loaded: boolean; busy: boolean; unlocked: boolean; error: string;
  vaults: VaultMetadata[]; selectedId: string | null; entries: UnlockedEntry[]; preferences: SecurityPreferences; lockEpoch: number }
type Operation = { signal: AbortSignal }
const initial = (): Snapshot => ({ ownerId: null, loaded: false, busy: false, unlocked: false, error: '',
  vaults: [], selectedId: null, entries: [], preferences: { ...DEFAULT_PREFERENCES }, lockEpoch: 0 })

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

  constructor(api: VaultApi, derive: DeriveKey, clock = Date.now) { this.#api = api; this.#derive = derive; this.#clock = clock }
  getSnapshot = () => this.#state
  subscribe = (listener: () => void) => { this.#listeners.add(listener); return () => { this.#listeners.delete(listener) } }
  #publish(patch: Partial<Snapshot>) { this.#state = { ...this.#state, ...patch }; this.#listeners.forEach((listener) => listener()) }

  lock = () => {
    this.#epoch += 1
    this.#abort?.abort()
    this.#key = null
    this.#publish({ entries: [], unlocked: false, busy: false, error: '', lockEpoch: this.#state.lockEpoch + 1 })
  }

  switchAccount(ownerId: number | null, enabled: boolean) {
    this.lock()
    this.#state = { ...initial(), ownerId, lockEpoch: this.#state.lockEpoch }
    this.#publish({})
    if (ownerId !== null && enabled) void this.load()
  }

  async #run(action: (op: Operation) => Promise<{ patch: Partial<Snapshot>; key?: CryptoKey }>): Promise<boolean> {
    if (this.#state.busy || this.#state.ownerId === null) return false
    const epoch = ++this.#epoch
    const abort = new AbortController()
    this.#abort = abort
    this.#publish({ busy: true, error: '' })
    try {
      const result = await action({ signal: abort.signal })
      if (epoch !== this.#epoch || abort.signal.aborted) return false
      if (result.key) { this.#key = result.key; this.#lastActivity = this.#clock() }
      this.#publish({ ...result.patch, busy: false })
      return true
    } catch (error) {
      if (epoch !== this.#epoch || abort.signal.aborted) return false
      if (error instanceof VaultDataError || !(error instanceof ApiError) || [401, 403].includes(error.status)) this.lock()
      this.#publish({ busy: false, error: error instanceof VaultDataError ? error.message : accountError(error) })
      return false
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
    return { key, patch: { vaults: [saved], selectedId: saved.id, unlocked: true, entries: [], loaded: true } }
  })

  async #readEntries(key: CryptoKey, id: string, signal: AbortSignal) {
    const envelopes = await this.#api.entries(id, signal)
    const entries: UnlockedEntry[] = []
    for (const envelope of envelopes) {
      signal.throwIfAborted()
      entries.push({ envelope, data: await decryptEntry(key, envelope) })
    }
    return entries
  }

  unlock = (master: string) => this.#run(async ({ signal }) => {
    const metadata = this.#state.vaults.find((vault) => vault.id === this.#state.selectedId)
    if (!metadata) throw new VaultDataError('Load and select your vault first.')
    const key = await unlockEncryptedVault(metadata, master, this.#derive, signal)
    const entries = await this.#readEntries(key, metadata.id, signal)
    return { key, patch: { entries, unlocked: true } }
  })

  refresh = () => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.selectedId) throw new VaultDataError('Unlock your vault first.')
    return { patch: { entries: await this.#readEntries(this.#key, this.#state.selectedId, signal) } }
  })

  save = (value: EntryPayload, existingId?: string, expectedRevision?: number) => this.#run(async ({ signal }) => {
    if (!this.#key || !this.#state.unlocked || !this.#state.selectedId) throw new VaultDataError('Unlock your vault first.')
    const data = validatePayload(value)
    const existing = existingId ? this.#state.entries.find((entry) => entry.envelope.id === existingId) : undefined
    if (existingId && !existing) throw new VaultDataError('Refresh before editing this entry.')
    if (existing && expectedRevision !== existing.envelope.revision) throw new ApiError('Entry changed. Close the editor and refresh before saving.', 409)
    const id = existingId ?? crypto.randomUUID()
    const revision = existing ? existing.envelope.revision + 1 : 1
    const encrypted = await encryptEntry(this.#key, this.#state.selectedId, id, revision, data)
    signal.throwIfAborted()
    const envelope = await this.#api.save(this.#state.selectedId, id, revision, encrypted, signal)
    return { patch: { entries: [{ envelope, data }, ...this.#state.entries.filter((entry) => entry.envelope.id !== id)] } }
  })

  remove = (id: string, expectedRevision: number) => this.#run(async ({ signal }) => {
    const entry = this.#state.entries.find((item) => item.envelope.id === id)
    if (!this.#key || !entry) throw new VaultDataError('Unlock and refresh before deleting.')
    if (expectedRevision !== entry.envelope.revision) throw new ApiError('Entry changed. Close the editor and refresh before deleting.', 409)
    await this.#api.remove(entry.envelope, signal)
    return { patch: { entries: this.#state.entries.filter((item) => item.envelope.id !== id) } }
  })

  updatePreferences = (value: SecurityPreferences) => this.#run(async ({ signal }) => ({ patch: { preferences: await this.#api.updatePreferences(value, signal) } }))

  checkIdle = () => {
    const elapsed = this.#clock() - this.#lastActivity
    if (this.#state.unlocked && (elapsed < 0 || elapsed >= this.#state.preferences.auto_lock_seconds * 1000)) this.lock()
  }
  touch = () => { this.checkIdle(); if (this.#state.unlocked) this.#lastActivity = this.#clock() }
  hidden = () => { if (this.#state.preferences.lock_on_hidden) this.lock() }
}
