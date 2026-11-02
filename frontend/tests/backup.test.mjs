import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createDecipheriv } from 'node:crypto'
import { BackupError, createBackup, openBackup } from '../src/vault/backup.ts'
import { deriveArgon2id } from '../src/vault/argon2.ts'
import { fromBase64, toBase64 } from '../src/vault/format.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const signal = () => new AbortController().signal
const password = 'PUBLIC independent backup passphrase 374!'
const derive = (value, salt) => deriveArgon2id(new TextEncoder().encode(value), salt)
const records = [{ envelope: fixture.entry, data: fixture.payload }]
const archive = await createBackup(fixture.vault.id, records, password, derive, signal())

test('exports an independently encrypted archive and restores every field and whitespace', async () => {
  for (const value of [password, fixture.master, fixture.payload.password, fixture.payload.title, fixture.payload.username]) assert.ok(!archive.includes(value))
  const opened = await openBackup(archive, password, derive, signal())
  assert.deepEqual(opened.content.entries[0].payload, fixture.payload)
  assert.notEqual(opened.backupId, fixture.vault.id)
  assert.equal(opened.archiveDigest.length, 64)
  const file = JSON.parse(archive)
  assert.notEqual(file.encryption.kdf_salt, fixture.vault.kdf_salt)
  assert.notEqual(file.encryption.wrapped_key, fixture.vault.wrapped_key)
  assert.equal(Object.keys(file).sort().join(','), 'ciphertext,encryption,format,nonce,version')
})

test('backup AES-GCM content and wrapped key decrypt using independent Node crypto', async () => {
  const file = JSON.parse(archive)
  const raw = await derive(password, fromBase64(file.encryption.kdf_salt, 16))
  function decrypt(key, nonce, ciphertext, aad) {
    const encrypted = fromBase64(ciphertext, 17, 32 * 1024 * 1024 + 16)
    const decipher = createDecipheriv('aes-256-gcm', key, fromBase64(nonce, 12))
    decipher.setAAD(Buffer.from(aad))
    decipher.setAuthTag(encrypted.subarray(-16))
    return Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()])
  }
  const dataKey = decrypt(raw, file.encryption.wrap_nonce, file.encryption.wrapped_key,
    `velnar.safevault:1:wrap:${file.encryption.id}:argon2id:19:65536:3:4:${file.encryption.kdf_salt}`)
  const content = JSON.parse(decrypt(dataKey, file.nonce, file.ciphertext, `velnar.safevault:1:backup:${file.encryption.id}`).toString('utf8'))
  assert.deepEqual(content.entries[0].payload, fixture.payload)
  raw.fill(0)
  dataKey.fill(0)
})

test('wrong passwords, altered content, nonce and truncated archives fail closed', async () => {
  await assert.rejects(openBackup(archive, 'PUBLIC incorrect backup password', derive, signal()), BackupError)
  const file = JSON.parse(archive)
  const bytes = fromBase64(file.ciphertext, 17, 32 * 1024 * 1024 + 16)
  bytes[0] ^= 1
  for (const changes of [{ ciphertext: toBase64(bytes) }, { nonce: toBase64(new Uint8Array(12)) }, { ciphertext: file.ciphertext.slice(4) }]) {
    await assert.rejects(openBackup(JSON.stringify({ ...file, ...changes }), password, derive, signal()), BackupError)
  }
  await assert.rejects(openBackup(archive.slice(0, -10), password, derive, signal()), BackupError)
})

test('unknown versions, fields and hostile KDF parameters fail before derivation', async () => {
  let calls = 0
  const forbidden = async () => { calls += 1; throw new Error('must not derive') }
  const file = JSON.parse(archive)
  for (const changes of [{ version: 2 }, { plaintext: 'secret' }, { encryption: { ...file.encryption, kdf_memory_kib: 2 ** 30 } }]) {
    await assert.rejects(openBackup(JSON.stringify({ ...file, ...changes }), password, forbidden, signal()), BackupError)
  }
  assert.equal(calls, 0)
})

test('format whitespace and property order do not defeat duplicate-restore detection', async () => {
  const file = JSON.parse(archive)
  const reordered = JSON.stringify({ version: file.version, ciphertext: file.ciphertext, format: file.format,
    nonce: file.nonce, encryption: Object.fromEntries(Object.entries(file.encryption).reverse()) }, null, 2)
  const first = await openBackup(archive, password, derive, signal())
  const second = await openBackup(reordered, password, derive, signal())
  assert.equal(first.archiveDigest, second.archiveDigest)
})

test('empty vault backups are valid and cancelled work returns no archive', async () => {
  const empty = await createBackup(fixture.vault.id, [], password, derive, signal())
  assert.deepEqual((await openBackup(empty, password, derive, signal())).content.entries, [])
  const abort = new AbortController()
  abort.abort()
  await assert.rejects(createBackup(fixture.vault.id, records, password, derive, abort.signal), { name: 'AbortError' })
  await assert.rejects(openBackup(archive, password, derive, abort.signal), { name: 'AbortError' })
})
