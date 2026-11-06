import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createVaultApi } from '../src/vault/api.ts'
import { VaultController } from '../src/vault/controller.ts'
import { encryptEntry, importDataKey } from '../src/vault/crypto.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const first = crypto.randomUUID()
const second = crypto.randomUUID()
const preferences = { auto_lock_seconds: 300, lock_on_hidden: true }

test('a page from a different vault snapshot is rejected even if the count matches', async () => {
  const requests = []
  const api = createVaultApi(async (path) => {
    requests.push(path)
    return requests.length === 1
      ? { count: 2, next: 'page2', results: [fixture.entry], version: first }
      : { count: 2, next: null, results: [{ ...fixture.entry, id: crypto.randomUUID() }], version: second }
  })
  let published
  await assert.rejects(api.entries(fixture.vault.id, new AbortController().signal, (version) => { published = version }),
    (error) => error.status === 409)
  assert.equal(published, undefined)
})

test('sync applies the newer remote version and rejects an editor based on the previous one', async () => {
  let version = first
  let remote = fixture.entry
  let writes = 0
  const api = {
    vaults: async () => [fixture.vault],
    preferences: async () => preferences,
    entries: async (_id, _signal, report) => { report(version); return [remote] },
    entriesVersion: async () => version,
    save: async () => { writes += 1 },
  }
  const derive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
  const controller = new VaultController(api, derive)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  assert.equal(await controller.unlock(fixture.master), true)
  assert.equal(controller.getSnapshot().entriesVersion, first)

  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const data = { ...fixture.payload, title: 'Edited on another device' }
  remote = { ...fixture.entry, revision: 2, ...await encryptEntry(key, fixture.vault.id, fixture.entry.id, 2, data) }
  version = second
  await controller.sync()
  assert.equal(controller.getSnapshot().entriesVersion, second)
  assert.deepEqual(controller.getSnapshot().entries[0].data, data)
  assert.equal(await controller.save(fixture.payload, fixture.entry.id, 1, 1), false)
  assert.equal(writes, 0)
  assert.equal(controller.getSnapshot().unlocked, true)
})

test('locking while a background sync is in flight prevents plaintext from coming back', async () => {
  let finish
  let started
  const waiting = new Promise((resolve) => { started = resolve })
  const api = {
    vaults: async () => [fixture.vault],
    preferences: async () => preferences,
    entries: async (_id, _signal, report) => { report(first); return [fixture.entry] },
    entriesVersion: async () => {
      started()
      return new Promise((resolve) => { finish = resolve })
    },
  }
  const derive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
  const controller = new VaultController(api, derive)
  controller.switchAccount(1, false)
  await controller.load()
  await controller.unlock(fixture.master)
  const syncing = controller.sync()
  await waiting
  controller.lock()
  finish(second)
  await syncing
  assert.equal(controller.getSnapshot().entriesVersion, null)
  assert.deepEqual(controller.getSnapshot().entries, [])
})

test('a newly created vault syncs before its first unlock or manual refresh', async () => {
  const api = {
    vaults: async () => [],
    preferences: async () => preferences,
    create: async (vault) => vault,
    entriesVersion: async () => second,
    entries: async (_id, _signal, report) => { report(second); return [] },
  }
  const controller = new VaultController(api, async () => new Uint8Array(32).fill(12))
  controller.switchAccount(1, false)
  await controller.load()
  assert.equal(await controller.create('Public synthetic master password'), true)
  assert.equal(controller.getSnapshot().entriesVersion, null)
  await controller.sync()
  assert.equal(controller.getSnapshot().entriesVersion, second)
  assert.equal(controller.getSnapshot().unlocked, true)
})
