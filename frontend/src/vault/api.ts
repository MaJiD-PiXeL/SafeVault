import { accountApi, ApiError } from '../api.ts'
import { fromBase64, object, readKeyVersion, UUID, validateEnvelope, validatePreferences, validateRecoveryEnvelope, validateVault, VaultDataError } from './format.ts'
import type { EncryptedEntry, RecoveryEnvelope, SecurityPreferences, VaultMetadata } from './format.ts'

type Request = (path: string, method?: string, body?: unknown, signal?: AbortSignal, timeoutMs?: number) => Promise<unknown>
type EntryVersion = Pick<EncryptedEntry, 'id' | 'revision' | 'state_version' | 'nonce'> & {
  lifecycle?: Pick<EncryptedEntry, 'deleted_at' | 'updated_at'>
}
const MAX_VAULT_ENTRIES = 5000
const MAX_VAULT_CIPHERTEXT = 32 * 1024 * 1024
const MAX_PAGE_CIPHERTEXT = 5 * 1024 * 1024
const MAX_INCREMENTAL_FETCHES = 8
export type RestoreReceipt = { backup_id: string; archive_digest: string; entry_count: number; already_restored: boolean }
export type RestoreEnvelope = { id: string; nonce: string; ciphertext: string }
function validateReceipt(value: unknown, backupId: string): RestoreReceipt {
  if (!object(value) || value.backup_id !== backupId || typeof value.archive_digest !== 'string' ||
      !/^[0-9a-f]{64}$/.test(value.archive_digest) || !Number.isInteger(value.entry_count) ||
      (value.entry_count as number) < 1 || (value.entry_count as number) > 5000 || typeof value.already_restored !== 'boolean') throw new VaultDataError()
  return value as RestoreReceipt
}
function vaultPath(id: string) {
  if (!UUID.test(id)) throw new VaultDataError()
  return `vaults/${id}/entries`
}

function readVersion(value: unknown): string {
  if (typeof value !== 'string' || !UUID.test(value)) throw new VaultDataError('Invalid vault snapshot version.')
  return value
}

function versions(entry: EncryptedEntry) {
  return { expected_revision: entry.revision, expected_state_version: entry.state_version }
}

function readEntryVersion(value: unknown): EntryVersion {
  const validCounter = (counter: unknown): counter is number =>
    typeof counter === 'number' && Number.isSafeInteger(counter) && counter >= 1 && counter <= 2147483647
  if (!object(value) || typeof value.id !== 'string' || !UUID.test(value.id) ||
      !validCounter(value.revision) || !validCounter(value.state_version) || typeof value.nonce !== 'string') throw new VaultDataError()
  fromBase64(value.nonce, 12)
  const entry = { id: value.id, revision: value.revision, state_version: value.state_version, nonce: value.nonce }
  const { deleted_at, updated_at } = value
  if (deleted_at === undefined && updated_at === undefined) return entry
  const validDate = (date: unknown): date is string => typeof date === 'string' && Number.isFinite(Date.parse(date))
  if (!validDate(updated_at) || (deleted_at !== null && !validDate(deleted_at))) throw new VaultDataError()
  return { ...entry, lifecycle: { deleted_at, updated_at } }
}

function sameContentVersion(left: EncryptedEntry | null | undefined, right: EntryVersion): left is EncryptedEntry {
  return left?.id === right.id && left.revision === right.revision && left.nonce === right.nonce
}

function keyVersionField(keyVersion: number | undefined) {
  return keyVersion === undefined ? {} : { expected_key_version: readKeyVersion(keyVersion) }
}

function checkKeyVersion(value: unknown, expected: number) {
  if (readKeyVersion(value) !== expected) throw new VaultDataError('The vault encryption key changed. Unlock the vault again.')
}

function expectedWrapper(old: VaultMetadata) {
  return { expected_kdf_salt: old.kdf_salt, expected_wrap_nonce: old.wrap_nonce, expected_wrapped_key: old.wrapped_key }
}

export function sameWrapper(left: VaultMetadata, right: VaultMetadata) {
  return left.id === right.id && (left.key_version ?? 1) === (right.key_version ?? 1) && left.kdf_salt === right.kdf_salt &&
    left.wrap_nonce === right.wrap_nonce && left.wrapped_key === right.wrapped_key
}

function wrapperReplacement(old: VaultMetadata, vault: VaultMetadata) {
  if (vault.id !== old.id || vault.kdf_salt === old.kdf_salt || vault.wrap_nonce === old.wrap_nonce ||
      vault.wrapped_key === old.wrapped_key) throw new VaultDataError('A fresh key wrapper is required.')
  return {
    ...expectedWrapper(old),
    kdf_salt: vault.kdf_salt, wrap_nonce: vault.wrap_nonce, wrapped_key: vault.wrapped_key,
  }
}

function validateTransition(value: unknown, entry: EncryptedEntry, trashed: boolean) {
  const result = validateEnvelope(value, entry.vault_id)
  if (result.id !== entry.id || result.revision !== entry.revision || result.state_version !== entry.state_version + 1 ||
      result.nonce !== entry.nonce || result.ciphertext !== entry.ciphertext || (result.deleted_at !== null) !== trashed) throw new VaultDataError()
  return result
}

export function createVaultApi(request: Request = accountApi.vaultRequest) {
  async function entriesVersion(id: string, signal: AbortSignal, expectedKeyVersion = 1) {
    if (!UUID.test(id)) throw new VaultDataError()
    const data = await request(`vaults/${id}/entries-version`, 'GET', undefined, signal)
    if (!object(data)) throw new VaultDataError()
    checkKeyVersion(data.key_version, expectedKeyVersion)
    return readVersion(data.version)
  }

  async function entry(vaultId: string, id: string, signal: AbortSignal, timeoutMs?: number) {
    if (!UUID.test(id)) throw new VaultDataError()
    try {
      const result = validateEnvelope(await request(`${vaultPath(vaultId)}/${id}`, 'GET', undefined, signal, timeoutMs), vaultId)
      if (result.id !== id) throw new VaultDataError()
      return result
    } catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error }
  }

  return {
    async vaults(signal: AbortSignal): Promise<VaultMetadata[]> {
      const data = await request('vaults', 'GET', undefined, signal)
      if (!object(data) || !Array.isArray(data.vaults) || data.vaults.length > 10) throw new VaultDataError()
      const vaults = data.vaults.map(validateVault)
      if (new Set(vaults.map((vault) => vault.id)).size !== vaults.length) throw new VaultDataError()
      return vaults
    },
    async create(value: VaultMetadata, signal: AbortSignal) {
      const vault = validateVault(value)
      if (vault.key_version !== undefined || vault.recovery) throw new VaultDataError()
      const result = validateVault(await request('vaults', 'POST', vault, signal))
      if (!sameWrapper(result, vault) || result.recovery) throw new VaultDataError()
      return result
    },
    async changeMasterPassword(previous: VaultMetadata, value: VaultMetadata, signal: AbortSignal) {
      const old = validateVault(previous)
      const vault = validateVault(value)
      if (vault.key_version !== old.key_version) throw new VaultDataError()
      const result = validateVault(await request(`vaults/${old.id}/master-password`, 'POST', wrapperReplacement(old, vault), signal))
      if (!sameWrapper(result, vault)) throw new VaultDataError()
      return result
    },
    async setupRecovery(previous: VaultMetadata, value: RecoveryEnvelope | null, signal: AbortSignal) {
      const old = validateVault(previous)
      const recovery = value === null ? null : validateRecoveryEnvelope(value)
      const result = validateVault(await request(`vaults/${old.id}/recovery-key`, 'POST', {
        ...expectedWrapper(old), expected_key_version: old.key_version ?? 1, expected_recovery: old.recovery ?? null, recovery,
      }, signal))
      if (!sameWrapper(result, old) || JSON.stringify(result.recovery ?? null) !== JSON.stringify(recovery)) throw new VaultDataError()
      return result
    },
    async recoverVault(previous: VaultMetadata, value: VaultMetadata, signal: AbortSignal) {
      const old = validateVault(previous)
      const vault = validateVault(value)
      if (!old.recovery || vault.recovery || vault.key_version !== old.key_version) throw new VaultDataError()
      const result = validateVault(await request(`vaults/${old.id}/recover`, 'POST', {
        ...wrapperReplacement(old, vault), expected_key_version: old.key_version ?? 1, expected_recovery: old.recovery,
      }, signal))
      if (!sameWrapper(result, vault) || result.recovery) throw new VaultDataError()
      return result
    },
    async rotateKey(previous: VaultMetadata, value: VaultMetadata, entriesVersion: string, entries: RestoreEnvelope[], signal: AbortSignal) {
      const old = validateVault(previous)
      const vault = validateVault(value)
      const keyVersion = old.key_version ?? 1
      if (vault.key_version !== keyVersion + 1) throw new VaultDataError()
      const result = validateVault(await request(`vaults/${old.id}/key-rotation`, 'POST', {
        ...wrapperReplacement(old, vault), expected_key_version: keyVersion, expected_entries_version: readVersion(entriesVersion),
        entries: entries.map(({ id, nonce, ciphertext }) => ({ id, nonce, ciphertext })),
      }, signal, 60000))
      if (JSON.stringify(result) !== JSON.stringify(vault)) throw new VaultDataError()
      return result
    },
    entriesVersion,
    async entriesDelta(id: string, current: EncryptedEntry[], signal: AbortSignal, expectedKeyVersion = 1) {
      if (!UUID.test(id)) throw new VaultDataError()
      let data: unknown
      try { data = await request(`vaults/${id}/entries-manifest`, 'GET', undefined, signal) }
      catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error }
      if (!object(data) || !Array.isArray(data.entries) || data.entries.length > MAX_VAULT_ENTRIES) throw new VaultDataError()
      checkKeyVersion(data.key_version, expectedKeyVersion)
      const version = readVersion(data.version)
      const manifest = data.entries.map(readEntryVersion)
      if (new Set(manifest.map((item) => item.id)).size !== manifest.length) throw new VaultDataError()
      const entries = new Map(current.map((item) => [item.id, item]))
      const changed: EntryVersion[] = []
      for (const item of manifest) {
        const cached = entries.get(item.id)
        if (!sameContentVersion(cached, item)) {
          changed.push(item)
        } else if (cached.state_version !== item.state_version) {
          if (item.lifecycle) entries.set(item.id, { ...cached, ...item.lifecycle, state_version: item.state_version })
          else changed.push(item)
        }
      }
      if (changed.length > MAX_INCREMENTAL_FETCHES || (changed.length > 0 && changed.length === manifest.length)) return null

      if (changed.length) {
        const controller = new AbortController()
        const readSignal = AbortSignal.any([signal, controller.signal])
        const stale = () => new ApiError('Vault changed during loading. Refresh and try again.', 409)
        try {
          const results = await Promise.all(changed.map(async (item) => {
            const result = await entry(id, item.id, readSignal, 60000)
            if (!sameContentVersion(result, item) || result.state_version !== item.state_version) throw stale()
            return result
          }))
          if (await entriesVersion(id, readSignal, expectedKeyVersion) !== version) throw stale()
          for (const item of results) entries.set(item.id, item)
        } finally { controller.abort() }
      }
      const envelopes = manifest.map((item) => entries.get(item.id)!)
      if (envelopes.reduce((size, item) => size + item.ciphertext.length, 0) > MAX_VAULT_CIPHERTEXT) {
        throw new VaultDataError('This vault is too large for this client.')
      }
      return { envelopes, entriesVersion: version }
    },
    async entries(id: string, signal: AbortSignal, onVersion?: (version: string) => void, expectedKeyVersion = 1): Promise<EncryptedEntry[]> {
      const entries: EncryptedEntry[] = []
      const seen = new Set<string>()
      let count = -1
      let totalBytes = 0
      let version: string | null = null
      let bounded = true
      const path = vaultPath(id)
      for (let page = 1; page <= MAX_VAULT_ENTRIES; page += 1) {
        const position = bounded ? `offset=${entries.length}` : `page=${page}`
        const data = await request(`${path}?state=all&${position}`, 'GET', undefined, signal, 60000)
        signal.throwIfAborted()
        if (!object(data) || typeof data.count !== 'number' || !Number.isSafeInteger(data.count) || data.count < 0 ||
            !Array.isArray(data.results) || data.results.length > 50) throw new VaultDataError()
        checkKeyVersion(data.key_version, expectedKeyVersion)
        const pageVersion = data.version === undefined ? null : readVersion(data.version)
        if (page > 1 && version !== pageVersion) throw new ApiError('Vault changed during loading. Refresh and try again.', 409)
        version = pageVersion
        if (data.count > MAX_VAULT_ENTRIES) throw new VaultDataError('This vault is too large for this client.')
        if (count !== -1 && count !== data.count) throw new VaultDataError('Vault changed during loading. Refresh and try again.')
        count = data.count
        // Older servers ignore the initial offset and return their first numbered page.
        if (page === 1) bounded = 'next_offset' in data
        if (bounded && version === null) throw new VaultDataError('Missing vault snapshot version.')
        const next = bounded ? data.next_offset : data.next
        const batch = data.results.map((item) => validateEnvelope(item, id))
        const end = entries.length + batch.length
        if (end > count || (end === count) !== (next === null) ||
            (next !== null && (!batch.length || (bounded ? next !== end : typeof next !== 'string' || page >= 100)))) {
          throw new VaultDataError('Invalid vault pagination.')
        }
        const pageBytes = batch.reduce((size, item) => size + item.ciphertext.length, 0)
        if (bounded && pageBytes > MAX_PAGE_CIPHERTEXT) throw new VaultDataError('Vault page exceeds the ciphertext limit.')
        totalBytes += pageBytes
        if (totalBytes > MAX_VAULT_CIPHERTEXT) throw new VaultDataError('This vault is too large for this client.')
        for (const entry of batch) {
          if (seen.has(entry.id)) throw new VaultDataError('Vault changed during loading. Refresh and try again.')
          seen.add(entry.id)
        }
        entries.push(...batch)
        if (next === null) {
          if (version !== null) onVersion?.(version)
          return entries
        }
      }
      throw new VaultDataError('This vault is too large for this client.')
    },
    entry,
    async save(vaultId: string, id: string, revision: number, encrypted: { nonce: string; ciphertext: string }, signal: AbortSignal, stateVersion = 1, keyVersion?: number) {
      if (!UUID.test(id)) throw new VaultDataError()
      const { nonce, ciphertext } = encrypted
      const timeout = ciphertext.length > 128 * 1024 ? 60000 : undefined
      const data = revision === 1
        ? await request(vaultPath(vaultId), 'POST', { id, nonce, ciphertext, ...keyVersionField(keyVersion) }, signal, timeout)
        : await request(`${vaultPath(vaultId)}/${id}`, 'PATCH', { nonce, ciphertext, expected_revision: revision - 1,
          expected_state_version: stateVersion, ...keyVersionField(keyVersion) }, signal, timeout)
      const result = validateEnvelope(data, vaultId)
      if (result.id !== id || result.revision !== revision || result.state_version !== (revision === 1 ? 1 : stateVersion) ||
          result.deleted_at !== null || result.nonce !== nonce || result.ciphertext !== ciphertext) throw new VaultDataError()
      return result
    },
    async remove(entry: EncryptedEntry, signal: AbortSignal, keyVersion?: number) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      return validateTransition(await request(`${vaultPath(entry.vault_id)}/${entry.id}`, 'DELETE', { ...versions(entry), ...keyVersionField(keyVersion) }, signal), entry, true)
    },
    async restoreEntry(entry: EncryptedEntry, signal: AbortSignal, keyVersion?: number) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      return validateTransition(await request(`${vaultPath(entry.vault_id)}/${entry.id}/restore`, 'POST', { ...versions(entry), ...keyVersionField(keyVersion) }, signal), entry, false)
    },
    async purge(entry: EncryptedEntry, signal: AbortSignal, keyVersion?: number) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      await request(`${vaultPath(entry.vault_id)}/${entry.id}/purge`, 'DELETE', { ...versions(entry), ...keyVersionField(keyVersion) }, signal)
    },
    async preferences(signal: AbortSignal) {
      return validatePreferences(await request('security-settings', 'GET', undefined, signal))
    },
    async updatePreferences(value: SecurityPreferences, signal: AbortSignal) {
      return validatePreferences(await request('security-settings', 'PATCH', validatePreferences(value), signal))
    },
    async restoreReceipt(vaultId: string, backupId: string, signal: AbortSignal) {
      if (!UUID.test(vaultId) || !UUID.test(backupId)) throw new VaultDataError()
      try { return validateReceipt(await request(`vaults/${vaultId}/restores/${backupId}`, 'GET', undefined, signal), backupId) }
      catch (error) { if (error instanceof ApiError && error.status === 404) return null; throw error }
    },
    async restore(vaultId: string, backupId: string, archiveDigest: string, entries: RestoreEnvelope[], signal: AbortSignal, keyVersion?: number) {
      if (!UUID.test(vaultId) || !UUID.test(backupId) || !/^[0-9a-f]{64}$/.test(archiveDigest)) throw new VaultDataError()
      const result = validateReceipt(await request(`vaults/${vaultId}/restores`, 'POST', {
        backup_id: backupId, archive_digest: archiveDigest, ...keyVersionField(keyVersion),
        entries: entries.map(({ id, nonce, ciphertext }) => ({ id, nonce, ciphertext })),
      }, signal, 60000), backupId)
      if (result.archive_digest !== archiveDigest || result.entry_count !== entries.length) throw new VaultDataError()
      return result
    },
  }
}

export type VaultApi = ReturnType<typeof createVaultApi>
