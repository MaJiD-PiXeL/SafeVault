import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { createDecipheriv } from 'node:crypto'
import { test } from 'node:test'
import { deriveArgon2id } from '../src/vault/argon2.ts'
import { createEncryptedVault, decryptEntry, encryptEntry, importDataKey, unlockEncryptedVault } from '../src/vault/crypto.ts'
import { entryAAD, fromBase64, toBase64, validatePayload, validateVault, VaultDataError, wrapAAD } from '../src/vault/format.ts'
import { generatePassword } from '../src/vault/generator.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const signal = () => new AbortController().signal
const derive = (password, salt, abort) => {
  abort.throwIfAborted()
  return deriveArgon2id(new TextEncoder().encode(password), salt)
}
const fixtureDerive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))

test('Argon2id v1 matches independently generated Python cryptography bytes', async () => {
  const key = await deriveArgon2id(new TextEncoder().encode(fixture.master), fromBase64(fixture.vault.kdf_salt, 16))
  assert.equal(Buffer.from(key).toString('hex'), fixture.wrapping_key_hex)
  const trimmed = await deriveArgon2id(new TextEncoder().encode(fixture.master.trim()), fromBase64(fixture.vault.kdf_salt, 16))
  assert.notDeepEqual(key, trimmed)
  key.fill(0)
  trimmed.fill(0)
})

test('opens an independent Python envelope with exact UTF-8 AAD and nonextractable keys', async () => {
  assert.equal(new TextDecoder().decode(wrapAAD(fixture.vault)), fixture.wrap_aad)
  assert.equal(new TextDecoder().decode(entryAAD(fixture.vault.id, fixture.entry.id, 1)), fixture.entry_aad)
  const key = await unlockEncryptedVault(fixture.vault, fixture.master, derive, signal())
  assert.equal(key.extractable, false)
  await assert.rejects(crypto.subtle.exportKey('raw', key))
  assert.deepEqual(await decryptEntry(key, fixture.entry), fixture.payload)
})

test('fresh client ciphertext decrypts with independent Node AES-GCM and preserves all fields', async () => {
  const rawKey = Buffer.from(fixture.data_key_hex, 'hex')
  const key = await importDataKey(rawKey)
  const encrypted = await encryptEntry(key, fixture.vault.id, fixture.entry.id, 2, fixture.payload)
  const bytes = fromBase64(encrypted.ciphertext, 17, 65552)
  const decipher = createDecipheriv('aes-256-gcm', rawKey, fromBase64(encrypted.nonce, 12))
  decipher.setAAD(Buffer.from(entryAAD(fixture.vault.id, fixture.entry.id, 2)))
  decipher.setAuthTag(bytes.subarray(-16))
  const plain = Buffer.concat([decipher.update(bytes.subarray(0, -16)), decipher.final()]).toString('utf8')
  assert.deepEqual(JSON.parse(plain), fixture.payload)
  assert.equal(Object.keys(encrypted).sort().join(','), 'ciphertext,nonce')
  const again = await encryptEntry(key, fixture.vault.id, fixture.entry.id, 2, fixture.payload)
  assert.notEqual(again.nonce, encrypted.nonce)
  assert.notEqual(again.ciphertext, encrypted.ciphertext)
})

test('rejects wrong master password, wrong key, tampering and substituted AAD', async () => {
  await assert.rejects(unlockEncryptedVault(fixture.vault, 'wrong master password', derive, signal()), VaultDataError)
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const wrong = await importDataKey(crypto.getRandomValues(new Uint8Array(32)))
  await assert.rejects(decryptEntry(wrong, fixture.entry), VaultDataError)
  const bytes = fromBase64(fixture.entry.ciphertext, 17, 65552)
  bytes[0] ^= 1
  for (const changes of [{ ciphertext: toBase64(bytes) }, { revision: 2 },
    { id: crypto.randomUUID() }, { vault_id: crypto.randomUUID() }, { nonce: toBase64(new Uint8Array(12)) }]) {
    await assert.rejects(decryptEntry(key, { ...fixture.entry, ...changes }), VaultDataError)
  }
})

test('rejects unsupported KDF allocations and malformed metadata before deriving a key', async () => {
  let calls = 0
  const forbidden = async () => { calls += 1; throw new Error('must not derive') }
  for (const changes of [{ kdf_memory_kib: 2 ** 31 }, { kdf_iterations: 1 }, { kdf_parallelism: 1 },
    { format_version: 2 }, { kdf: 'pbkdf2' }, { kdf_salt: 'not base64' }, { wrap_nonce: toBase64(new Uint8Array(11)) }]) {
    await assert.rejects(unlockEncryptedVault({ ...fixture.vault, ...changes }, fixture.master, forbidden, signal()), VaultDataError)
  }
  assert.equal(calls, 0)
  await assert.rejects(unlockEncryptedVault(fixture.vault, 'invalid Unicode \ud800', forbidden, signal()), /invalid Unicode/)
  assert.equal(calls, 0)
  for (const value of ['Zh==', 'Zg==\n', '!!!!', '', null]) assert.throws(() => fromBase64(value, 1), VaultDataError)
})

test('creates independently salted vault keys and can reopen the generated vault', async () => {
  const first = await createEncryptedVault(fixture.master, derive, signal())
  const second = await createEncryptedVault(fixture.master, derive, signal())
  validateVault(first.vault)
  assert.notEqual(first.vault.id, second.vault.id)
  assert.notEqual(first.vault.kdf_salt, second.vault.kdf_salt)
  assert.notEqual(first.vault.wrap_nonce, second.vault.wrap_nonce)
  assert.notEqual(first.vault.wrapped_key, second.vault.wrapped_key)
  const id = crypto.randomUUID()
  const encrypted = await encryptEntry(first.key, first.vault.id, id, 1, fixture.payload)
  const reopened = await unlockEncryptedVault(first.vault, fixture.master, derive, signal())
  assert.deepEqual(await decryptEntry(reopened, { ...fixture.entry, ...encrypted, id, vault_id: first.vault.id }), fixture.payload)
  await assert.rejects(decryptEntry(second.key, { ...fixture.entry, ...encrypted, id, vault_id: first.vault.id }), VaultDataError)
})

test('clears derived bytes and rejects corrupted wrapped-key authentication', async () => {
  const derived = new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
  await unlockEncryptedVault(fixture.vault, fixture.master, async () => derived, signal())
  assert.ok(derived.every((value) => value === 0))
  const bytes = fromBase64(fixture.vault.wrapped_key, 48)
  bytes[47] ^= 1
  await assert.rejects(unlockEncryptedVault({ ...fixture.vault, wrapped_key: toBase64(bytes) }, fixture.master, fixtureDerive, signal()), VaultDataError)
})

test('payload types, schema and byte size are validated after authentication', async () => {
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const base = { schema_version: 1, title: 'Example', password: '  secret  ' }
  assert.deepEqual(validatePayload(base), { ...base, username: '', website: '', notes: '', category: '', favorite: false })
  for (const changes of [{ schema_version: 2 }, { title: ' ' }, { favorite: 'true' }, { notes: null }, { owner: 1 }]) {
    assert.throws(() => validatePayload({ ...base, ...changes }), VaultDataError)
  }
  await assert.rejects(encryptEntry(key, fixture.vault.id, fixture.entry.id, 1, { ...fixture.payload, notes: '🔐'.repeat(20000) }), /64 KiB/)
  const invalid = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: fromBase64(fixture.entry.nonce, 12),
    additionalData: entryAAD(fixture.vault.id, fixture.entry.id, 1), tagLength: 128 }, key,
    new TextEncoder().encode(JSON.stringify({ schema_version: 2, password: 'must not be shown' })))
  await assert.rejects(decryptEntry(key, { ...fixture.entry, ciphertext: toBase64(new Uint8Array(invalid)) }), VaultDataError)
})

test('generator uses cryptographic randomness and includes every character group', (t) => {
  t.mock.method(Math, 'random', () => { throw new Error('weak randomness forbidden') })
  for (const length of [12, 20, 128]) {
    const password = generatePassword(length)
    assert.equal(password.length, length)
    for (const group of [/[A-Z]/, /[a-z]/, /[0-9]/, /[^a-zA-Z0-9]/]) assert.match(password, group)
  }
  for (const length of [1, 129, 12.5, NaN]) assert.throws(() => generatePassword(length))
})
