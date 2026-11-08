import { decodeEntryPayload, encodeEntryPayload, entryAAD, fromBase64, MAX_ENTRY_CIPHERTEXT_BYTES, MAX_ENTRY_PLAINTEXT_BYTES,
  PROFILE, toBase64, validateVault, VaultDataError, wrapAAD } from './format.ts'
import type { EncryptedEntry, EntryPayload, VaultMetadata } from './format.ts'

export type DeriveKey = (password: string, salt: Uint8Array, signal: AbortSignal) => Promise<Uint8Array>

function requireCrypto() {
  if (!globalThis.crypto?.subtle) throw new VaultDataError('Vault encryption requires HTTPS or localhost with Web Crypto support.')
}

async function wrapDataKey(vault: VaultMetadata, bytes: Uint8Array<ArrayBuffer>, master: string, derive: DeriveKey, signal: AbortSignal) {
  const metadata = { ...vault, kdf_salt: toBase64(crypto.getRandomValues(new Uint8Array(16))),
    wrap_nonce: toBase64(crypto.getRandomValues(new Uint8Array(12))) }
  const wrapper = await wrappingKey(master, metadata.kdf_salt, derive, signal)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fromBase64(metadata.wrap_nonce, 12),
    additionalData: wrapAAD(metadata), tagLength: 128 }, wrapper, bytes)
  signal.throwIfAborted()
  return { ...metadata, wrapped_key: toBase64(new Uint8Array(encrypted)) }
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
  validateNewMaster(currentMaster, newMaster)
  const bytes = await unwrapDataKey(previous, currentMaster, derive, signal)
  try {
    const vault = await wrapDataKey(previous, bytes, newMaster, derive, signal)
    return { vault, key: await importDataKey(bytes) }
  } finally { bytes.fill(0) }
}

function validateNewMaster(currentMaster: string, newMaster: string) {
  if (newMaster.length < 12 || newMaster.length > 1024) throw new VaultDataError('Use 12–1,024 characters for your new master password.')
  if (currentMaster === newMaster) throw new VaultDataError('Choose a different master password.')
}

function recoveryAAD(vault: VaultMetadata) {
  return new TextEncoder().encode(`velnar.safevault:1:recovery:${vault.id}:${vault.key_version ?? 1}`)
}

export async function createRecoveryKey(value: unknown, master: string, derive: DeriveKey, signal: AbortSignal) {
  const vault = validateVault(value)
  const bytes = await unwrapDataKey(vault, master, derive, signal)
  const secret = crypto.getRandomValues(new Uint8Array(32))
  try {
    const key = await importDataKey(secret)
    const nonce = crypto.getRandomValues(new Uint8Array(12))
    const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: recoveryAAD(vault), tagLength: 128 }, key, bytes)
    signal.throwIfAborted()
    return { code: `SV1-${toBase64(secret).slice(0, -1).replaceAll('+', '-').replaceAll('/', '_')}`,
      recovery: { nonce: toBase64(nonce), wrapped_key: toBase64(new Uint8Array(wrapped)) } }
  } finally { secret.fill(0); bytes.fill(0) }
}

export async function rewrapWithRecovery(value: unknown, code: string, newMaster: string, derive: DeriveKey, signal: AbortSignal) {
  const previous = validateVault(value)
  validateNewMaster('', newMaster)
  const recovery = previous.recovery
  if (!recovery) throw new VaultDataError('No recovery key is active for this vault.')
  const trimmed = code.trim()
  if (!/^SV1-[A-Za-z0-9_-]{43}$/.test(trimmed)) throw new VaultDataError('Enter the complete vault recovery key.')
  const secret = fromBase64(`${trimmed.slice(4).replaceAll('-', '+').replaceAll('_', '/')}=`, 32)
  let bytes: Uint8Array<ArrayBuffer> | undefined
  try {
    const key = await importDataKey(secret)
    try {
      bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(recovery.nonce, 12),
        additionalData: recoveryAAD(previous), tagLength: 128 }, key, fromBase64(recovery.wrapped_key, 48)))
    } catch { throw new VaultDataError('This recovery key could not open the vault.') }
    signal.throwIfAborted()
    const vault = await wrapDataKey(previous, bytes, newMaster, derive, signal)
    delete vault.recovery
    return { vault, key: await importDataKey(bytes) }
  } finally { secret.fill(0); bytes?.fill(0) }
}

export async function prepareKeyRotation(value: unknown, envelopes: EncryptedEntry[], currentMaster: string, newMaster: string, derive: DeriveKey, signal: AbortSignal) {
  const previous = validateVault(value)
  validateNewMaster(currentMaster, newMaster)
  const keyVersion = (previous.key_version ?? 1) + 1
  if (keyVersion > 2147483647) throw new VaultDataError('Vault key rotation limit reached.')
  const oldKey = await unlockEncryptedVault(previous, currentMaster, derive, signal)
  const bytes = crypto.getRandomValues(new Uint8Array(32))
  let vault: VaultMetadata
  let newKey: CryptoKey
  try {
    vault = await wrapDataKey({ ...previous, key_version: keyVersion }, bytes, newMaster, derive, signal)
    delete vault.recovery
    newKey = await importDataKey(bytes)
  } finally { bytes.fill(0) }

  const entries = []
  const usedNonces = new Set(envelopes.map((entry) => entry.nonce))
  for (const envelope of envelopes) {
    signal.throwIfAborted()
    if (envelope.vault_id !== previous.id) throw new VaultDataError()
    const plaintext = await decryptEntryBytes(oldKey, envelope)
    try {
      signal.throwIfAborted()
      parseEntry(plaintext)
      const aad = entryAAD(previous.id, envelope.id, envelope.revision)
      entries.push({ id: envelope.id, ...await encryptEntryBytes(newKey, aad, plaintext, usedNonces) })
    } finally { plaintext.fill(0) }
  }
  signal.throwIfAborted()
  return { vault, entries }
}

async function encryptEntryBytes(key: CryptoKey, aad: Uint8Array<ArrayBuffer>, bytes: Uint8Array<ArrayBuffer>, usedNonces?: Set<string>) {
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const encoded = toBase64(nonce)
  if (usedNonces?.has(encoded)) throw new VaultDataError('Random nonce collision. Start rotation again.')
  usedNonces?.add(encoded)
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, key, bytes)
  return { nonce: encoded, ciphertext: toBase64(new Uint8Array(encrypted)) }
}

export async function encryptEntry(key: CryptoKey, vaultId: string, id: string, revision: number, value: EntryPayload) {
  const payload = encodeEntryPayload(value)
  const bytes = new TextEncoder().encode(JSON.stringify(payload))
  try {
    if (bytes.length > MAX_ENTRY_PLAINTEXT_BYTES) throw new VaultDataError('Entry is too large to encrypt.')
    return await encryptEntryBytes(key, entryAAD(vaultId, id, revision), bytes)
  } finally { bytes.fill(0) }
}

async function decryptEntryBytes(key: CryptoKey, envelope: EncryptedEntry) {
  try {
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(envelope.nonce, 12),
      additionalData: entryAAD(envelope.vault_id, envelope.id, envelope.revision), tagLength: 128 },
      key, fromBase64(envelope.ciphertext, 17, MAX_ENTRY_CIPHERTEXT_BYTES)))
  } catch { throw new VaultDataError() }
}

function parseEntry(bytes: Uint8Array) {
  try { return decodeEntryPayload(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))) }
  catch { throw new VaultDataError() }
}

export async function decryptEntry(key: CryptoKey, envelope: EncryptedEntry): Promise<EntryPayload> {
  const bytes = await decryptEntryBytes(key, envelope)
  try { return parseEntry(bytes) }
  finally { bytes.fill(0) }
}
