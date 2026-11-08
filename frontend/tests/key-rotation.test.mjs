import assert from 'node:assert/strict'
import { createDecipheriv } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { ApiError } from '../src/api.ts'
import { createVaultApi } from '../src/vault/api.ts'
import { deriveArgon2id } from '../src/vault/argon2.ts'
import { VaultController } from '../src/vault/controller.ts'
import { decryptEntry, encryptEntry, importDataKey, prepareKeyRotation, unlockEncryptedVault } from '../src/vault/crypto.ts'
import { entryAAD, fromBase64, wrapAAD } from '../src/vault/format.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const next = '  Synthetic replacement for rotation 🔑  '
const derive = (password, salt) => deriveArgon2id(new TextEncoder().encode(password), salt)
const version = crypto.randomUUID()
const signal = () => new AbortController().signal

function openBytes(key, nonce, aad, ciphertext) {
  const bytes = Buffer.from(ciphertext, 'base64')
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(nonce, 'base64'))
  decipher.setAAD(aad)
  decipher.setAuthTag(bytes.subarray(-16))
  return Buffer.concat([decipher.update(bytes.subarray(0, -16)), decipher.final()])
}

test('rotation creates a different AES key and preserves exact plaintext bytes and AAD for active and trashed rows', async () => {
  const oldRaw = Buffer.from(fixture.data_key_hex, 'hex')
  const key = await importDataKey(oldRaw)
  const id = crypto.randomUUID()
  const note = { schema_version: 2, kind: 'note', title: 'Synthetic note', notes: ' Exact text ', category: '', favorite: true }
  const trashed = { ...fixture.entry, id, revision: 3, state_version: 2, deleted_at: fixture.entry.updated_at,
    ...await encryptEntry(key, fixture.vault.id, id, 3, note) }
  const original = [fixture.entry, trashed]
  const { vault, entries } = await prepareKeyRotation(fixture.vault, original, fixture.master, next, derive, signal())
  assert.equal(vault.key_version, 2)
  const wrappingKey = await derive(next, fromBase64(vault.kdf_salt, 16))
  const newRaw = openBytes(wrappingKey, vault.wrap_nonce, wrapAAD(vault), vault.wrapped_key)
  assert.notDeepEqual(newRaw, oldRaw)
  const unlocked = await unlockEncryptedVault(vault, next, derive, signal())
  await assert.rejects(unlockEncryptedVault(vault, fixture.master, derive, signal()))
  for (const [index, previous] of original.entries()) {
    const { id, nonce, ciphertext } = entries[index]
    const aad = entryAAD(previous.vault_id, id, previous.revision)
    assert.equal(id, previous.id)
    assert.notEqual(nonce, previous.nonce)
    assert.deepEqual(openBytes(newRaw, nonce, aad, ciphertext), openBytes(oldRaw, previous.nonce, aad, previous.ciphertext))
    await assert.rejects(decryptEntry(key, { ...previous, nonce, ciphertext }))
    assert.deepEqual(await decryptEntry(unlocked, { ...previous, nonce, ciphertext }), index === 0 ? fixture.payload : note)
  }
})

function mockVaultServer() {
  let vault = fixture.vault
  let envelope = fixture.entry
  let snapshot = version
  let dropResponse = false
  let rotationRequests = 0
  const requests = []
  const api = createVaultApi(async (path, method, body) => {
    requests.push({ path, method, body })
    if (path === 'vaults') return { vaults: [vault] }
    if (path === 'security-settings') return { auto_lock_seconds: 300, lock_on_hidden: true }
    if (path.endsWith('/entries?state=all&page=1')) return { results: [envelope], count: 1, next: null, version: snapshot, key_version: vault.key_version ?? 1 }
    if (path.endsWith('/entries-version')) return { version: snapshot, key_version: vault.key_version ?? 1 }
    if (path.endsWith('/key-rotation')) {
      rotationRequests += 1
      assert.equal(body.expected_entries_version, snapshot)
      assert.equal(body.expected_key_version, 1)
      assert.deepEqual(Object.keys(body.entries[0]).sort(), ['ciphertext', 'id', 'nonce'])
      assert.equal(JSON.stringify(body).includes(next), false)
      assert.equal(JSON.stringify(body).includes(fixture.master), false)
      const { kdf_salt, wrap_nonce, wrapped_key, entries } = body
      vault = { ...vault, kdf_salt, wrap_nonce, wrapped_key, key_version: 2 }
      envelope = { ...envelope, ...entries[0] }
      snapshot = crypto.randomUUID()
      if (dropResponse) throw new TypeError('Connection lost after commit')
      return vault
    }
    if (path.endsWith('/entries') && method === 'POST') {
      if (body.expected_key_version !== vault.key_version) throw new ApiError('The vault encryption key changed. Unlock the vault again.', 409, 'vault_key_changed')
      return { ...fixture.entry, ...body, revision: 1, state_version: 1, deleted_at: null }
    }
    throw new Error(`Unexpected request ${method} ${path}`)
  })
  return { api, requests, lostResponse: () => { dropResponse = true }, rotations: () => rotationRequests,
    corruptEntry: () => { envelope = { ...envelope, nonce: Buffer.alloc(12, 9).toString('base64') } } }
}

async function client(api, deriveKey = derive) {
  const controller = new VaultController(api, deriveKey)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  assert.equal(await controller.unlock(fixture.master), true)
  return controller
}

test('other devices lock on a write or a sync after rotation and use the new key version after unlocking', async () => {
  const { api, requests } = mockVaultServer()
  const [first, writer, watcher] = await Promise.all([client(api), client(api), client(api)])
  assert.equal(await first.rotateKey(fixture.master, next), true)
  assert.equal(first.getSnapshot().unlocked, false)
  assert.match(first.getSnapshot().keyRotationResult, /rotated/)
  assert.equal(await writer.save(fixture.payload), false)
  assert.equal(writer.getSnapshot().unlocked, false)
  assert.deepEqual(writer.getSnapshot().entries, [])
  await watcher.sync()
  assert.equal(watcher.getSnapshot().unlocked, false)
  assert.match(watcher.getSnapshot().error, /key changed/)
  assert.equal(await writer.unlock(next), true)
  assert.deepEqual(writer.getSnapshot().entries[0].data, fixture.payload)
  assert.equal(await writer.save(fixture.payload), true)
  assert.equal(requests.at(-1).body.expected_key_version, 2)
})

test('a lost commit response locks and discards stale metadata without retrying', async () => {
  const server = mockVaultServer()
  const controller = await client(server.api)
  server.lostResponse()
  assert.equal(await controller.rotateKey(fixture.master, next), false)
  assert.equal(controller.getSnapshot().loaded, false)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.match(controller.getSnapshot().error, /could not be confirmed/)
  assert.equal(server.rotations(), 1)
  assert.equal(await controller.load(), true)
  assert.equal(await controller.unlock(next), true)
  assert.deepEqual(controller.getSnapshot().entries[0].data, fixture.payload)
})

test('corrupted records discovered in the fresh rotation snapshot prevent any submission', async () => {
  const server = mockVaultServer()
  const controller = await client(server.api)
  server.corruptEntry()
  assert.equal(await controller.rotateKey(fixture.master, next), false)
  assert.equal(server.rotations(), 0)
  assert.equal(controller.getSnapshot().unlocked, false)
})
