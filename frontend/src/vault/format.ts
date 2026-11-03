export const PROFILE = Object.freeze({ format_version: 1, cipher: 'AES-256-GCM', kdf: 'argon2id',
  kdf_version: 19, kdf_memory_kib: 65536, kdf_iterations: 3, kdf_parallelism: 4 } as const)
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export type VaultMetadata = typeof PROFILE & { id: string; kdf_salt: string; wrap_nonce: string; wrapped_key: string }
export type EncryptedEntry = { id: string; vault_id: string; nonce: string; ciphertext: string;
  revision: number; state_version: number; deleted_at: string | null; created_at: string; updated_at: string }
export type EntryPayload = { schema_version: 1; title: string; username: string; password: string;
  website: string; notes: string; category: string; favorite: boolean }
export type UnlockedEntry = { envelope: EncryptedEntry; data: EntryPayload }
export type SecurityPreferences = { auto_lock_seconds: number; lock_on_hidden: boolean }
export const DEFAULT_PREFERENCES: SecurityPreferences = { auto_lock_seconds: 300, lock_on_hidden: true }

export class VaultDataError extends Error {
  constructor(message = 'Vault data could not be authenticated. Check your master password and vault data.') {
    super(message)
    this.name = 'VaultDataError'
  }
}

export function object(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

export function toBase64(bytes: Uint8Array): string {
  let text = ''
  for (const byte of bytes) text += String.fromCharCode(byte)
  return btoa(text)
}

export function fromBase64(value: unknown, minimum: number, maximum = minimum): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || value.length > 4 * Math.ceil(maximum / 3)) throw new VaultDataError()
  try {
    const bytes = Uint8Array.from(atob(value), (char) => char.charCodeAt(0))
    if (bytes.length < minimum || bytes.length > maximum || toBase64(bytes) !== value) throw new VaultDataError()
    return bytes
  } catch { throw new VaultDataError() }
}

export function validateVault(value: unknown): VaultMetadata {
  if (!object(value) || typeof value.id !== 'string' || !UUID.test(value.id) ||
      Object.entries(PROFILE).some(([name, expected]) => value[name] !== expected)) throw new VaultDataError()
  fromBase64(value.kdf_salt, 16)
  fromBase64(value.wrap_nonce, 12)
  fromBase64(value.wrapped_key, 48)
  return { ...PROFILE, id: value.id, kdf_salt: value.kdf_salt as string,
    wrap_nonce: value.wrap_nonce as string, wrapped_key: value.wrapped_key as string }
}

export function validateEnvelope(value: unknown, vaultId: string): EncryptedEntry {
  if (!object(value) || typeof value.id !== 'string' || !UUID.test(value.id) || value.vault_id !== vaultId ||
      !Number.isSafeInteger(value.revision) || (value.revision as number) < 1 || (value.revision as number) > 2147483647 ||
      !Number.isSafeInteger(value.state_version) || (value.state_version as number) < 1 || (value.state_version as number) > 2147483647 ||
      (value.deleted_at !== null && (typeof value.deleted_at !== 'string' || !Number.isFinite(Date.parse(value.deleted_at)))) ||
      typeof value.created_at !== 'string' || !Number.isFinite(Date.parse(value.created_at)) ||
      typeof value.updated_at !== 'string' || !Number.isFinite(Date.parse(value.updated_at))) throw new VaultDataError()
  fromBase64(value.nonce, 12)
  fromBase64(value.ciphertext, 17, 65552)
  return { id: value.id, vault_id: vaultId, nonce: value.nonce as string, ciphertext: value.ciphertext as string,
    revision: value.revision as number, state_version: value.state_version as number, deleted_at: value.deleted_at as string | null,
    created_at: value.created_at, updated_at: value.updated_at }
}

export function validatePayload(value: unknown): EntryPayload {
  if (!object(value) || value.schema_version !== 1 ||
      Object.keys(value).some((key) => !['schema_version', 'title', 'username', 'password', 'website', 'notes', 'category', 'favorite'].includes(key)) ||
      typeof value.title !== 'string' || !value.title.trim() || typeof value.password !== 'string' || !value.password ||
      ['username', 'website', 'notes', 'category'].some((name) => value[name] !== undefined && typeof value[name] !== 'string') ||
      (value.favorite !== undefined && typeof value.favorite !== 'boolean')) throw new VaultDataError('Invalid entry fields.')
  return { schema_version: 1, title: value.title, username: value.username as string ?? '', password: value.password,
    website: value.website as string ?? '', notes: value.notes as string ?? '', category: value.category as string ?? '',
    favorite: value.favorite as boolean ?? false }
}

export function validatePreferences(value: unknown): SecurityPreferences {
  if (!object(value) || !Number.isInteger(value.auto_lock_seconds) || (value.auto_lock_seconds as number) < 60 ||
      (value.auto_lock_seconds as number) > 3600 || typeof value.lock_on_hidden !== 'boolean') throw new VaultDataError('Invalid security settings.')
  return { auto_lock_seconds: value.auto_lock_seconds as number, lock_on_hidden: value.lock_on_hidden }
}

export function wrapAAD(vault: VaultMetadata): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(`velnar.safevault:1:wrap:${vault.id}:argon2id:19:65536:3:4:${vault.kdf_salt}`)
}

export function entryAAD(vaultId: string, entryId: string, revision: number): Uint8Array<ArrayBuffer> {
  if (!UUID.test(vaultId) || !UUID.test(entryId) || !Number.isSafeInteger(revision) || revision < 1 || revision > 2147483647) throw new VaultDataError()
  return new TextEncoder().encode(`velnar.safevault:1:entry:${vaultId}:${entryId}:${revision}`)
}
