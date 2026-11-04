import assert from 'node:assert/strict'
import { createHash, createDecipheriv } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { ApiError, createAccountApi } from '../src/api.ts'
import { createVaultApi } from '../src/vault/api.ts'
import { VaultController } from '../src/vault/controller.ts'
import { decryptEntry, encryptEntry, importDataKey, rewrapEncryptedVault, unlockEncryptedVault } from '../src/vault/crypto.ts'
import { deriveArgon2id } from '../src/vault/argon2.ts'
import { fromBase64, wrapAAD } from '../src/vault/format.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const nextPassword = '  PUBLIC replacement master 🔑  '
const signal = () => new AbortController().signal
const realDerive = (password, salt) => deriveArgon2id(new TextEncoder().encode(password), salt)
const fastDerive = async (password, salt, abort) => {
  abort.throwIfAborted()
  if (password === fixture.master && Buffer.from(salt).toString('base64') === fixture.vault.kdf_salt) return new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
  return new Uint8Array(createHash('sha256').update(password).update(salt).digest())
}
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done }); return { promise, resolve } }

test('real Argon2id rewrap preserves the data key, opens all original fields and rejects the old password', async () => {
  const old = structuredClone(fixture.vault)
  const { vault, key } = await rewrapEncryptedVault(old, fixture.master, nextPassword, realDerive, signal())
  assert.deepEqual(old, fixture.vault)
  assert.equal(vault.id, old.id)
  for (const field of ['kdf_salt', 'wrap_nonce', 'wrapped_key']) assert.notEqual(vault[field], old[field])
  assert.equal(key.extractable, false)
  await assert.rejects(crypto.subtle.exportKey('raw', key))
  assert.deepEqual(await decryptEntry(key, fixture.entry), fixture.payload)
  const reopened = await unlockEncryptedVault(vault, nextPassword, realDerive, signal())
  assert.deepEqual(await decryptEntry(reopened, fixture.entry), fixture.payload)
  await assert.rejects(unlockEncryptedVault(vault, fixture.master, realDerive, signal()))
  const wrapper = await realDerive(nextPassword, fromBase64(vault.kdf_salt, 16))
  const encrypted = Buffer.from(vault.wrapped_key, 'base64')
  const decipher = createDecipheriv('aes-256-gcm', wrapper, Buffer.from(vault.wrap_nonce, 'base64'))
  decipher.setAAD(Buffer.from(wrapAAD(vault)))
  decipher.setAuthTag(encrypted.subarray(-16))
  assert.equal(Buffer.concat([decipher.update(encrypted.subarray(0, -16)), decipher.final()]).toString('hex'), fixture.data_key_hex)
  wrapper.fill(0)
})

test('invalid replacements and wrong current passwords fail without a replacement wrapper', async () => {
  let calls = 0
  const derive = async (...args) => { calls += 1; return fastDerive(...args) }
  for (const password of ['short', fixture.master, 'x'.repeat(1025)]) {
    await assert.rejects(rewrapEncryptedVault(fixture.vault, fixture.master, password, derive, signal()))
  }
  assert.equal(calls, 0)
  await assert.rejects(rewrapEncryptedVault(fixture.vault, 'wrong current password', nextPassword, derive, signal()))
  assert.equal(calls, 1)
  await assert.rejects(rewrapEncryptedVault(fixture.vault, fixture.master, 'invalid Unicode \ud800', derive, signal()))
})

test('rewrap zeroes temporary plaintext key bytes and derived bytes on success and cancellation', async (t) => {
  const originalDecrypt = crypto.subtle.decrypt.bind(crypto.subtle)
  const rawKeys = []
  const derived = []
  t.mock.method(crypto.subtle, 'decrypt', async (...args) => {
    const buffer = await originalDecrypt(...args)
    rawKeys.push(new Uint8Array(buffer))
    return buffer
  })
  const derive = async (...args) => { const bytes = await fastDerive(...args); derived.push(bytes); return bytes }
  await rewrapEncryptedVault(fixture.vault, fixture.master, nextPassword, derive, signal())
  const abort = new AbortController()
  let count = 0
  await assert.rejects(rewrapEncryptedVault(fixture.vault, fixture.master, nextPassword, async (...args) => {
    const bytes = await derive(...args)
    if (++count === 2) abort.abort()
    return bytes
  }, abort.signal))
  assert.equal(rawKeys.length, 2)
  assert.ok([...rawKeys, ...derived].every(bytes => bytes.every(byte => byte === 0)))
})

test('account/vault transport sends only encrypted wrapper fields with CSRF and validates the saved result', async (t) => {
  const { vault } = await rewrapEncryptedVault(fixture.vault, fixture.master, nextPassword, fastDerive, signal())
  const requests = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    requests.push({ url, options })
    return Response.json(url.endsWith('/auth/session/') ? { user: { id: 1, username: 'synthetic' }, csrfToken: 'a'.repeat(64) } : vault)
  })
  const api = createVaultApi(createAccountApi('/api').vaultRequest)
  assert.deepEqual(await api.changeMasterPassword(fixture.vault, vault, signal()), vault)
  const write = requests.find(call => call.options.method === 'POST')
  assert.equal(write.url, `/api/vaults/${vault.id}/master-password/`)
  assert.equal(write.options.headers['X-CSRFToken'], 'a'.repeat(64))
  assert.deepEqual(Object.keys(JSON.parse(write.options.body)).sort(), ['expected_kdf_salt', 'expected_wrap_nonce', 'expected_wrapped_key', 'kdf_salt', 'wrap_nonce', 'wrapped_key'])
  for (const secret of [fixture.master, nextPassword, fixture.data_key_hex, fixture.payload.password]) assert.ok(!write.options.body.includes(secret))
  for (const changes of [{ id: crypto.randomUUID() }, { wrapped_key: fixture.vault.wrapped_key }, { kdf_salt: fixture.vault.kdf_salt }, { cipher: 'unsupported' }]) {
    await assert.rejects(createVaultApi(async () => ({ ...vault, ...changes })).changeMasterPassword(fixture.vault, vault, signal()))
  }
})

async function prepared(overrides = {}, entries = [fixture.entry], derive = fastDerive) {
  let metadata = structuredClone(fixture.vault)
  const calls = []
  const api = {
    vaults: async () => [structuredClone(metadata)],
    preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }),
    entries: async () => structuredClone(entries),
    changeMasterPassword: async (previous, next) => {
      calls.push({ previous, next })
      if (JSON.stringify(previous) !== JSON.stringify(metadata)) throw new ApiError('Conflict', 409)
      metadata = structuredClone(next)
      return structuredClone(metadata)
    },
    ...overrides,
  }
  const controller = new VaultController(api, derive)
  controller.switchAccount(1, false)
  await controller.load()
  assert.equal(await controller.unlock(fixture.master), true)
  return { controller, calls, api }
}

test('controller preserves active and trashed ciphertext and requires the new password after success', async () => {
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const id = crypto.randomUUID()
  const trash = { ...fixture.entry, id, deleted_at: new Date().toISOString(), state_version: 2,
    ...await encryptEntry(key, fixture.vault.id, id, 1, { ...fixture.payload, title: 'Trashed original' }) }
  const entries = [fixture.entry, trash]
  const original = structuredClone(entries)
  const { controller, calls } = await prepared({}, entries)
  assert.equal(await controller.changeMasterPassword(fixture.master, nextPassword), true)
  assert.equal(calls.length, 1)
  let state = controller.getSnapshot()
  assert.equal(state.unlocked, false)
  assert.deepEqual(state.entries, [])
  assert.deepEqual(state.trash, [])
  assert.match(state.masterPasswordResult, /changed/)
  assert.equal(state.backupExport, null)
  assert.equal(state.backupPreview, null)
  assert.deepEqual(entries, original)
  assert.equal(await controller.unlock(fixture.master), false)
  assert.equal(await controller.unlock(nextPassword), true)
  state = controller.getSnapshot()
  assert.deepEqual(state.entries[0].data, fixture.payload)
  assert.equal(state.trash[0].data.title, 'Trashed original')
  assert.deepEqual(state.entries[0].envelope, fixture.entry)
  assert.deepEqual(state.trash[0].envelope, trash)
})

test('wrong current password and corrupt records never submit a wrapper update', async () => {
  const { controller, calls, api } = await prepared()
  assert.equal(await controller.changeMasterPassword('wrong current password', nextPassword), false)
  assert.equal(calls.length, 0)
  assert.equal(await controller.unlock(fixture.master), true)
  api.entries = async () => [{ ...fixture.entry, id: crypto.randomUUID() }]
  assert.equal(await controller.changeMasterPassword(fixture.master, nextPassword), false)
  assert.equal(calls.length, 0)
})

test('unlock fetches the current wrapper after another device changes the master password', async () => {
  const { controller, api } = await prepared()
  const { vault } = await rewrapEncryptedVault(fixture.vault, fixture.master, nextPassword, fastDerive, signal())
  api.vaults = async () => [vault]
  controller.lock()
  assert.equal(controller.getSnapshot().vaults[0].wrapped_key, fixture.vault.wrapped_key)
  assert.equal(await controller.unlock(fixture.master), false)
  assert.equal(await controller.unlock(nextPassword), true)
  assert.equal(controller.getSnapshot().vaults[0].wrapped_key, vault.wrapped_key)
})

test('conflicts and uncertain outcomes lock, discard stale metadata and require reloading without replay', async () => {
  for (const failure of [new ApiError('Conflict', 409), new Error('Connection lost')]) {
    let attempts = 0
    const { controller } = await prepared({ changeMasterPassword: async () => { attempts += 1; throw failure } })
    assert.equal(await controller.changeMasterPassword(fixture.master, nextPassword), false)
    const state = controller.getSnapshot()
    assert.equal(state.unlocked, false)
    assert.equal(state.loaded, false)
    assert.deepEqual(state.vaults, [])
    assert.deepEqual(state.entries, [])
    assert.match(state.error, /could not be confirmed/)
    assert.equal(attempts, 1)
  }
})

test('a lock during derivation sends no update; late committed responses cannot republish data or metadata', async () => {
  const entered = deferred()
  const gate = deferred()
  const { controller } = await prepared({ changeMasterPassword: async (_previous, next) => { entered.resolve(); await gate.promise; return next } })
  const pending = controller.changeMasterPassword(fixture.master, nextPassword)
  await entered.promise
  controller.lock()
  gate.resolve()
  assert.equal(await pending, false)
  assert.equal(controller.getSnapshot().loaded, false)
  assert.deepEqual(controller.getSnapshot().vaults, [])
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.equal(controller.getSnapshot().masterPasswordResult, '')

  const deriving = deferred()
  const continueDeriving = deferred()
  let block = false
  const second = await prepared({}, [fixture.entry], async (...args) => {
    if (block) { deriving.resolve(); await continueDeriving.promise }
    return fastDerive(...args)
  })
  block = true
  const change = second.controller.changeMasterPassword(fixture.master, nextPassword)
  await deriving.promise
  second.controller.switchAccount(2, false)
  continueDeriving.resolve()
  assert.equal(await change, false)
  assert.equal(second.calls.length, 0)
  assert.equal(second.controller.getSnapshot().ownerId, 2)
  assert.deepEqual(second.controller.getSnapshot().entries, [])
})
