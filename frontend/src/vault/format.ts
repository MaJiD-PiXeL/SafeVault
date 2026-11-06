export const PROFILE = Object.freeze({ format_version: 1, cipher: 'AES-256-GCM', kdf: 'argon2id',
  kdf_version: 19, kdf_memory_kib: 65536, kdf_iterations: 3, kdf_parallelism: 4 } as const)
export const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
export type VaultMetadata = typeof PROFILE & { id: string; kdf_salt: string; wrap_nonce: string; wrapped_key: string }
export type EncryptedEntry = { id: string; vault_id: string; nonce: string; ciphertext: string;
  revision: number; state_version: number; deleted_at: string | null; created_at: string; updated_at: string }
type EntryFields = { title: string; notes: string; category: string; favorite: boolean }
export type PasswordPayload = EntryFields & { schema_version: 1; username: string; password: string; website: string }
export type NotePayload = EntryFields & { schema_version: 2; kind: 'note' }
export type CardPayload = EntryFields & { schema_version: 2; kind: 'card'; cardholder: string; card_number: string; expiry: string }
export type EntryPayload = PasswordPayload | NotePayload | CardPayload
export type EntryKind = 'password' | 'note' | 'card'
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
  if (!object(value) || typeof value.title !== 'string' || !value.title.trim() ||
      ['notes', 'category'].some((name) => value[name] !== undefined && typeof value[name] !== 'string') ||
      (value.favorite !== undefined && typeof value.favorite !== 'boolean')) throw new VaultDataError('Invalid entry fields.')
  const shared = { title: value.title, notes: value.notes as string ?? '', category: value.category as string ?? '',
    favorite: value.favorite as boolean ?? false }
  const commonKeys = ['schema_version', 'title', 'notes', 'category', 'favorite']
  const onlyKeys = (...fields: string[]) => Object.keys(value).every((key) => commonKeys.includes(key) || fields.includes(key))
  if (value.schema_version === 1 && onlyKeys('username', 'password', 'website') &&
      typeof value.password === 'string' && value.password &&
      (value.username === undefined || typeof value.username === 'string') &&
      (value.website === undefined || typeof value.website === 'string')) {
    // Retain the v1 field order used by existing backup content.
    return { schema_version: 1, title: shared.title, username: value.username ?? '', password: value.password,
      website: value.website ?? '', notes: shared.notes, category: shared.category, favorite: shared.favorite }
  }
  if (value.schema_version === 2) {
    if (value.kind === 'note' && onlyKeys('kind') && shared.notes.trim()) {
      return { schema_version: 2, kind: 'note', ...shared }
    }
    if (value.kind === 'card' && onlyKeys('kind', 'cardholder', 'card_number', 'expiry') &&
        typeof value.cardholder === 'string' && value.cardholder.length <= 200 &&
        typeof value.card_number === 'string' && /^[0-9]{12,19}$/.test(value.card_number) &&
        typeof value.expiry === 'string' && validCardExpiry(value.expiry)) {
      return { schema_version: 2, kind: 'card', ...shared, cardholder: value.cardholder,
        card_number: value.card_number, expiry: value.expiry }
    }
  }
  throw new VaultDataError('Invalid entry fields.')
}

export const validCardExpiry = (expiry: string) => expiry === '' || /^(0[1-9]|1[0-2])\/[0-9]{4}$/.test(expiry)

export function entryKind(data: EntryPayload): EntryKind {
  return data.schema_version === 1 ? 'password' : data.kind
}

export const ENTRY_LABELS: Record<EntryKind, string> = {
  password: 'password', note: 'secure note', card: 'payment card',
}

export function entrySummary(data: EntryPayload) {
  if (data.schema_version === 1) return { primary: data.username, secondary: data.website }
  if (data.kind === 'card') return { primary: data.cardholder || 'Payment card', secondary: `•••• ${data.card_number.slice(-4)}` }
  return { primary: 'Secure note', secondary: '' }
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
