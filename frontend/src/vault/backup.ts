import { createEncryptedVault, unlockEncryptedVault } from './crypto.ts'
import type { DeriveKey } from './crypto.ts'
import { decodeEntryPayload, encodeEntryPayload, fromBase64, object, PROFILE, toBase64, UUID, validateVault } from './format.ts'
import type { EntryPayload, UnlockedEntry, VaultMetadata } from './format.ts'

export const MAX_BACKUP_FILE_BYTES = 48 * 1024 * 1024
const MAX_CONTENT_BYTES = 32 * 1024 * 1024
const FORMAT = 'velnar.safevault.backup'
type RecordBackup = { original_id: string; original_revision: number; created_at: string; updated_at: string; payload: EntryPayload }
export type BackupContent = { version: 1; exported_at: string; source_vault_id: string; entries: RecordBackup[] }
export type OpenedBackup = { backupId: string; archiveDigest: string; content: BackupContent }

export class BackupError extends Error {
  constructor(message = 'Backup could not be authenticated. Check the backup password and file.') {
    super(message)
    this.name = 'BackupError'
  }
}

function exact(value: unknown, names: string[]): value is Record<string, unknown> {
  return object(value) && Object.keys(value).length === names.length && names.every((name) => Object.hasOwn(value, name))
}
const date = (value: unknown): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value))
const aad = (id: string) => new TextEncoder().encode(`velnar.safevault:1:backup:${id}`)

function validateContent(value: unknown): BackupContent {
  if (!exact(value, ['version', 'exported_at', 'source_vault_id', 'entries']) || value.version !== 1 ||
      !date(value.exported_at) || typeof value.source_vault_id !== 'string' || !UUID.test(value.source_vault_id) ||
      !Array.isArray(value.entries) || value.entries.length > 5000) throw new BackupError()
  const seen = new Set<string>()
  const entries = value.entries.map((record) => {
    if (!exact(record, ['original_id', 'original_revision', 'created_at', 'updated_at', 'payload']) ||
        typeof record.original_id !== 'string' || !UUID.test(record.original_id) || seen.has(record.original_id) ||
        !Number.isSafeInteger(record.original_revision) || (record.original_revision as number) < 1 ||
        (record.original_revision as number) > 2147483647 || !date(record.created_at) || !date(record.updated_at)) throw new BackupError()
    seen.add(record.original_id)
    const payload = decodeEntryPayload(record.payload)
    return { original_id: record.original_id, original_revision: record.original_revision as number,
      created_at: record.created_at, updated_at: record.updated_at, payload }
  })
  return { version: 1, exported_at: value.exported_at, source_vault_id: value.source_vault_id, entries }
}

export async function createBackup(sourceVaultId: string, entries: UnlockedEntry[], password: string,
  derive: DeriveKey, signal: AbortSignal): Promise<string> {
  let bytes: Uint8Array<ArrayBuffer> | undefined
  try {
    signal.throwIfAborted()
    if (password.length < 12 || password.length > 1024) throw new BackupError('Use a backup password of 12–1,024 characters.')
    const content = { version: 1, exported_at: new Date().toISOString(), source_vault_id: sourceVaultId,
      entries: entries.map(({ envelope, data }) => ({ original_id: envelope.id, original_revision: envelope.revision,
        created_at: envelope.created_at, updated_at: envelope.updated_at, payload: encodeEntryPayload(data) })) }
    validateContent(content)
    bytes = new TextEncoder().encode(JSON.stringify(content))
    if (bytes.length > MAX_CONTENT_BYTES) throw new BackupError('This backup exceeds the 32 MiB content limit.')
    // Independent salt AND random data key per archive. No nonce/key reuse with live entries.
    const { vault, key } = await createEncryptedVault(password, derive, signal)
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(vault.id), tagLength: 128 }, key, bytes)
    signal.throwIfAborted()
    return JSON.stringify({ format: FORMAT, version: 1, encryption: vault, nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(encrypted)) })
  } catch (error) {
    signal.throwIfAborted()
    throw error instanceof BackupError ? error : new BackupError('Backup creation failed. Check browser support and your backup password.')
  } finally { bytes?.fill(0) }
}

export async function openBackup(text: string, password: string, derive: DeriveKey, signal: AbortSignal): Promise<OpenedBackup> {
  let bytes: Uint8Array<ArrayBuffer> | undefined
  try {
    signal.throwIfAborted()
    if (text.length > MAX_BACKUP_FILE_BYTES || new TextEncoder().encode(text).length > MAX_BACKUP_FILE_BYTES) throw new BackupError('Backup file exceeds the 48 MiB limit.')
    const value: unknown = JSON.parse(text)
    if (!exact(value, ['format', 'version', 'encryption', 'nonce', 'ciphertext']) || value.format !== FORMAT || value.version !== 1 ||
        !exact(value.encryption, [...Object.keys(PROFILE), 'id', 'kdf_salt', 'wrap_nonce', 'wrapped_key'])) throw new BackupError('Unsupported or invalid backup format.')
    const encryption: VaultMetadata = validateVault(value.encryption)
    const nonce = fromBase64(value.nonce, 12)
    const encrypted = fromBase64(value.ciphertext, 17, MAX_CONTENT_BYTES + 16)
    const key = await unlockEncryptedVault(encryption, password, derive, signal)
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad(encryption.id), tagLength: 128 }, key, encrypted))
    signal.throwIfAborted()
    const content = validateContent(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)))
    // Canonical known-field order makes harmless JSON whitespace/key order irrelevant.
    const canonical = JSON.stringify({ format: FORMAT, version: 1, encryption, nonce: value.nonce, ciphertext: value.ciphertext })
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical)))
    signal.throwIfAborted()
    return { backupId: encryption.id, archiveDigest: Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join(''), content }
  } catch (error) {
    signal.throwIfAborted()
    throw error instanceof BackupError ? error : new BackupError()
  } finally { bytes?.fill(0) }
}
