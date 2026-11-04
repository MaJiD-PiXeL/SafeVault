import { entryAAD, fromBase64, PROFILE, toBase64, validatePayload, validateVault, VaultDataError, wrapAAD } from './format.ts'
import type { EncryptedEntry, EntryPayload, VaultMetadata } from './format.ts'

export type DeriveKey = (password: string, salt: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>

function requireCrypto() {
  if (!globalThis.crypto?.subtle) throw new VaultDataError('Vault encryption requires HTTPS or localhost with Web Crypto support.')
}

export async function importDataKey(bytes: Uint8Array): Promise<CryptoKey> {
  requireCrypto()
  if (bytes.length !== 32) throw new VaultDataError()
  return crypto.subtle.importKey('raw', new Uint8Array(bytes), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt'])
}

async function wrappingKey(master: string, salt: string, derive: DeriveKey, signal: AbortSignal) {
  signal.throwIfAborted()
  if (!master || master.length > 1024) throw new VaultDataError('Enter your master password (up to 1,024 characters).')
  for (const character of master) {
    const code = character.codePointAt(0)!
    if (code >= 0xd800 && code <= 0xdfff) throw new VaultDataError('Master password contains invalid Unicode.')
  }
  const bytes = await derive(master, fromBase64(salt, 16), signal)
  try { signal.throwIfAborted(); return await importDataKey(bytes) }
  finally { bytes.fill(0) }
}

export async function createEncryptedVault(master: string, derive: DeriveKey, signal: AbortSignal) {
  requireCrypto()
  if (master.length < 12) throw new VaultDataError('Use at least 12 characters for your master password.')
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  try {
    const vault: VaultMetadata = { ...PROFILE, id: crypto.randomUUID(), kdf_salt: toBase64(crypto.getRandomValues(new Uint8Array(16))),
      wrap_nonce: toBase64(crypto.getRandomValues(new Uint8Array(12))), wrapped_key: '' }
    const wrapper = await wrappingKey(master, vault.kdf_salt, derive, signal)
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fromBase64(vault.wrap_nonce, 12),
      additionalData: wrapAAD(vault), tagLength: 128 }, wrapper, bytes)
    signal.throwIfAborted()
    vault.wrapped_key = toBase64(new Uint8Array(wrapped))
    return { vault, key: await importDataKey(bytes) }
  } finally { bytes.fill(0) }
}

async function unwrapDataKey(vault: VaultMetadata, master: string, derive: DeriveKey, signal: AbortSignal) {
  const wrapper = await wrappingKey(master, vault.kdf_salt, derive, signal)
  let bytes: Uint8Array<ArrayBuffer> | undefined
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(vault.wrap_nonce, 12),
      additionalData: wrapAAD(vault), tagLength: 128 }, wrapper, fromBase64(vault.wrapped_key, 48)))
    signal.throwIfAborted()
    return bytes
  } catch (error) {
    bytes?.fill(0)
    signal.throwIfAborted()
    throw error instanceof VaultDataError ? error : new VaultDataError()
  }
}

export async function unlockEncryptedVault(value: unknown, master: string, derive: DeriveKey, signal: AbortSignal) {
  requireCrypto()
  const bytes = await unwrapDataKey(validateVault(value), master, derive, signal)
  try { return await importDataKey(bytes) }
  finally { bytes.fill(0) }
}

export async function rewrapEncryptedVault(value: unknown, currentMaster: string, newMaster: string, derive: DeriveKey, signal: AbortSignal) {
  requireCrypto()
  const previous = validateVault(value)
  if (newMaster.length < 12 || newMaster.length > 1024) throw new VaultDataError('Use 12–1,024 characters for your new master password.')
  if (currentMaster === newMaster) throw new VaultDataError('Choose a different master password.')
  const bytes = await unwrapDataKey(previous, currentMaster, derive, signal)
  try {
    const vault = { ...previous, kdf_salt: toBase64(crypto.getRandomValues(new Uint8Array(16))),
      wrap_nonce: toBase64(crypto.getRandomValues(new Uint8Array(12))) }
    const wrapper = await wrappingKey(newMaster, vault.kdf_salt, derive, signal)
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fromBase64(vault.wrap_nonce, 12),
      additionalData: wrapAAD(vault), tagLength: 128 }, wrapper, bytes)
    signal.throwIfAborted()
    vault.wrapped_key = toBase64(new Uint8Array(encrypted))
    return { vault, key: await importDataKey(bytes) }
  } finally { bytes.fill(0) }
}

export async function encryptEntry(key: CryptoKey, vaultId: string, id: string, revision: number, value: EntryPayload) {
  const payload = validatePayload(value)
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  try {
    if (bytes.length > 65536) throw new VaultDataError('Entry exceeds the 64 KiB limit.')
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: entryAAD(vaultId, id, revision), tagLength: 128 }, key, bytes)
    return { nonce: toBase64(nonce), ciphertext: toBase64(new Uint8Array(encrypted)) }
  } finally { bytes.fill(0) }
}

export async function decryptEntry(key: CryptoKey, envelope: EncryptedEntry): Promise<EntryPayload> {
  let bytes: Uint8Array | undefined
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(envelope.nonce, 12),
      additionalData: entryAAD(envelope.vault_id, envelope.id, envelope.revision), tagLength: 128 },
      key, fromBase64(envelope.ciphertext, 17, 65552)))
    return validatePayload(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)))
  } catch { throw new VaultDataError() }
  finally { bytes?.fill(0) }
}
