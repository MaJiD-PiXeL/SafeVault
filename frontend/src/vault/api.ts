import { accountApi, ApiError } from '../api.ts'
import { object, UUID, validateEnvelope, validatePreferences, validateVault, VaultDataError } from './format.ts'
import type { EncryptedEntry, SecurityPreferences, VaultMetadata } from './format.ts'

type Request = (path: string, method?: string, body?: unknown, signal?: AbortSignal, timeoutMs?: number) => Promise<unknown>
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

function versions(entry: EncryptedEntry) {
  return { expected_revision: entry.revision, expected_state_version: entry.state_version }
}

function validateTransition(value: unknown, entry: EncryptedEntry, trashed: boolean) {
  const result = validateEnvelope(value, entry.vault_id)
  if (result.id !== entry.id || result.revision !== entry.revision || result.state_version !== entry.state_version + 1 ||
      result.nonce !== entry.nonce || result.ciphertext !== entry.ciphertext || (result.deleted_at !== null) !== trashed) throw new VaultDataError()
  return result
}

export function createVaultApi(request: Request = accountApi.vaultRequest) {
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
      const result = validateVault(await request('vaults', 'POST', vault, signal))
      if (JSON.stringify(result) !== JSON.stringify(vault)) throw new VaultDataError()
      return result
    },
    async entries(id: string, signal: AbortSignal): Promise<EncryptedEntry[]> {
      const entries: EncryptedEntry[] = []
      let count = -1
      let totalBytes = 0
      for (let page = 1; page <= 100; page += 1) {
        const data = await request(`${vaultPath(id)}?state=all&page=${page}`, 'GET', undefined, signal)
        if (!object(data) || !Number.isSafeInteger(data.count) || (data.count as number) < 0 ||
            !Array.isArray(data.results) || data.results.length > 50 || (data.next !== null && typeof data.next !== 'string')) throw new VaultDataError()
        if ((data.count as number) > 5000) throw new VaultDataError('This vault is too large for this client.')
        if (count !== -1 && count !== data.count) throw new VaultDataError('Vault changed during loading. Refresh and try again.')
        count = data.count as number
        const batch = data.results.map((item) => validateEnvelope(item, id))
        totalBytes += batch.reduce((size, item) => size + item.ciphertext.length, 0)
        if (totalBytes > 32 * 1024 * 1024) throw new VaultDataError('This vault is too large for this client.')
        entries.push(...batch)
        if (new Set(entries.map((entry) => entry.id)).size !== entries.length) throw new VaultDataError('Vault changed during loading. Refresh and try again.')
        if (data.next === null) {
          if (entries.length !== count) throw new VaultDataError()
          return entries
        }
        // Construct our own same-origin page path; never follow response URLs.
      }
      throw new VaultDataError('This vault is too large for this client.')
    },
    async save(vaultId: string, id: string, revision: number, encrypted: { nonce: string; ciphertext: string }, signal: AbortSignal, stateVersion = 1) {
      if (!UUID.test(id)) throw new VaultDataError()
      const { nonce, ciphertext } = encrypted
      const data = revision === 1
        ? await request(vaultPath(vaultId), 'POST', { id, nonce, ciphertext }, signal)
        : await request(`${vaultPath(vaultId)}/${id}`, 'PATCH', { nonce, ciphertext, expected_revision: revision - 1, expected_state_version: stateVersion }, signal)
      const result = validateEnvelope(data, vaultId)
      if (result.id !== id || result.revision !== revision || result.state_version !== (revision === 1 ? 1 : stateVersion) ||
          result.deleted_at !== null || result.nonce !== nonce || result.ciphertext !== ciphertext) throw new VaultDataError()
      return result
    },
    async remove(entry: EncryptedEntry, signal: AbortSignal) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      return validateTransition(await request(`${vaultPath(entry.vault_id)}/${entry.id}`, 'DELETE', versions(entry), signal), entry, true)
    },
    async restoreEntry(entry: EncryptedEntry, signal: AbortSignal) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      return validateTransition(await request(`${vaultPath(entry.vault_id)}/${entry.id}/restore`, 'POST', versions(entry), signal), entry, false)
    },
    async purge(entry: EncryptedEntry, signal: AbortSignal) {
      if (!UUID.test(entry.id)) throw new VaultDataError()
      await request(`${vaultPath(entry.vault_id)}/${entry.id}/purge`, 'DELETE', versions(entry), signal)
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
    async restore(vaultId: string, backupId: string, archiveDigest: string, entries: RestoreEnvelope[], signal: AbortSignal) {
      if (!UUID.test(vaultId) || !UUID.test(backupId) || !/^[0-9a-f]{64}$/.test(archiveDigest)) throw new VaultDataError()
      const result = validateReceipt(await request(`vaults/${vaultId}/restores`, 'POST', {
        backup_id: backupId, archive_digest: archiveDigest,
        entries: entries.map(({ id, nonce, ciphertext }) => ({ id, nonce, ciphertext })),
      }, signal, 60000), backupId)
      if (result.archive_digest !== archiveDigest || result.entry_count !== entries.length) throw new VaultDataError()
      return result
    },
  }
}

export type VaultApi = ReturnType<typeof createVaultApi>
