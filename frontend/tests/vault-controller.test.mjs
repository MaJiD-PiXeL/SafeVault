import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { ApiError } from '../src/api.ts'
import { VaultController } from '../src/vault/controller.ts'
import { encryptEntry, importDataKey } from '../src/vault/crypto.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const derive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done }); return { promise, resolve } }

function fakeApi(overrides = {}) {
  const calls = []
  return {
    calls,
    vaults: async () => [fixture.vault],
    preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }),
    entries: async () => [fixture.entry],
    create: async (vault) => vault,
    save: async (vaultId, id, revision, encrypted) => {
      calls.push({ operation: 'save', vaultId, id, revision, encrypted })
      return { ...fixture.entry, ...encrypted, id, vault_id: vaultId, revision }
    },
    remove: async (entry) => { calls.push({ operation: 'remove', id: entry.id }) },
    updatePreferences: async (preferences) => preferences,
    ...overrides,
  }
}

async function prepared(api = fakeApi(), options = {}) {
  const controller = new VaultController(api, options.derive ?? derive, options.clock)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  return controller
}

test('manual lock drops decrypted entries and prevents further writes until unlock', async () => {
  const api = fakeApi()
  const controller = await prepared(api)
  assert.equal(await controller.unlock(fixture.master), true)
  assert.deepEqual(controller.getSnapshot().entries[0].data, fixture.payload)
  controller.lock()
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.ok(!JSON.stringify(controller.getSnapshot()).includes(fixture.payload.password))
  assert.equal(await controller.save(fixture.payload), false)
  assert.equal(api.calls.length, 0)
})

test('lock and account switches invalidate an in-flight key derivation', async () => {
  const result = deferred()
  const controller = await prepared(fakeApi(), { derive: () => result.promise })
  const pending = controller.unlock(fixture.master)
  controller.switchAccount(2, false)
  result.resolve(new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex')))
  assert.equal(await pending, false)
  assert.equal(controller.getSnapshot().ownerId, 2)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('a late successful server write cannot restore plaintext after locking', async () => {
  const started = deferred()
  const completed = deferred()
  const api = fakeApi({ save: async (vaultId, id, revision, encrypted) => {
    started.resolve()
    await completed.promise
    return { ...fixture.entry, ...encrypted, id, vault_id: vaultId, revision }
  } })
  const controller = await prepared(api)
  await controller.unlock(fixture.master)
  const save = controller.save(fixture.payload)
  await started.promise
  controller.lock()
  completed.resolve()
  assert.equal(await save, false)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('idle expiry is checked before accepting renewed activity', async () => {
  let now = 1000
  const controller = await prepared(fakeApi(), { clock: () => now })
  await controller.unlock(fixture.master)
  now += 299999
  controller.checkIdle()
  assert.equal(controller.getSnapshot().unlocked, true)
  now += 1
  controller.touch()
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('hidden-tab preference is enforced and explicit lock always clears data', async () => {
  const controller = await prepared()
  await controller.unlock(fixture.master)
  controller.hidden()
  assert.equal(controller.getSnapshot().unlocked, false)
  await controller.unlock(fixture.master)
  await controller.updatePreferences({ auto_lock_seconds: 60, lock_on_hidden: false })
  controller.hidden()
  assert.equal(controller.getSnapshot().unlocked, true)
  controller.lock()
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('an invalid record fails the entire unlock without returning partial plaintext', async () => {
  const controller = await prepared(fakeApi({ entries: async () => [fixture.entry, { ...fixture.entry, id: crypto.randomUUID() }] }))
  assert.equal(await controller.unlock(fixture.master), false)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.ok(!JSON.stringify(controller.getSnapshot()).includes(fixture.payload.password))
})

test('auth loss locks immediately while an edit conflict preserves the current unlocked data', async () => {
  let status = 409
  const controller = await prepared(fakeApi({ save: async () => { throw new ApiError('Refresh before saving.', status) } }))
  await controller.unlock(fixture.master)
  assert.equal(await controller.save(fixture.payload, fixture.entry.id, 1), false)
  assert.equal(controller.getSnapshot().unlocked, true)
  status = 403
  assert.equal(await controller.save(fixture.payload, fixture.entry.id, 1), false)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('stale editor versions cannot overwrite or delete data refreshed from another device', async () => {
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const updatedPayload = { ...fixture.payload, title: 'Newer device version' }
  const encrypted = await encryptEntry(key, fixture.vault.id, fixture.entry.id, 2, updatedPayload)
  let envelopes = [fixture.entry]
  const api = fakeApi({ entries: async () => envelopes })
  const controller = await prepared(api)
  await controller.unlock(fixture.master)
  envelopes = [{ ...fixture.entry, ...encrypted, revision: 2 }]
  await controller.refresh()
  assert.equal(await controller.save(fixture.payload, fixture.entry.id, 1), false)
  assert.equal(await controller.remove(fixture.entry.id, 1), false)
  assert.equal(api.calls.length, 0)
  assert.equal(controller.getSnapshot().entries[0].data.title, 'Newer device version')
})

test('successful edits use encrypted payloads and fresh revisions; removal clears the entry', async () => {
  const api = fakeApi()
  const controller = await prepared(api)
  await controller.unlock(fixture.master)
  assert.equal(await controller.save({ ...fixture.payload, favorite: false }, fixture.entry.id, 1), true)
  assert.equal(api.calls[0].revision, 2)
  assert.ok(!JSON.stringify(api.calls).includes(fixture.payload.password))
  assert.equal(controller.getSnapshot().entries[0].data.favorite, false)
  assert.equal(await controller.remove(fixture.entry.id, 2), true)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('reloading vault metadata and switching vaults both clear the previous key and data', async () => {
  const controller = await prepared()
  await controller.unlock(fixture.master)
  await controller.load()
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
  await controller.unlock(fixture.master)
  controller.select(fixture.vault.id)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('uncertain vault creation requires reloading metadata before another attempt', async () => {
  const controller = await prepared(fakeApi({ vaults: async () => [], create: async () => { throw new TypeError('network failure') } }))
  assert.equal(await controller.create(fixture.master), false)
  assert.equal(controller.getSnapshot().loaded, false)
  assert.equal(controller.getSnapshot().unlocked, false)
})
