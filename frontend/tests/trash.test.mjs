import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { ApiError, createAccountApi } from '../src/api.ts'
import { createVaultApi } from '../src/vault/api.ts'
import { VaultController } from '../src/vault/controller.ts'
import { decryptEntry, encryptEntry, importDataKey } from '../src/vault/crypto.ts'
import { openBackup } from '../src/vault/backup.ts'
import { analyzePasswords } from '../src/vault/health.ts'
import { validateEnvelope } from '../src/vault/format.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const derive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
const signal = () => new AbortController().signal
const deferred = () => { let resolve; const promise = new Promise(done => { resolve = done }); return { promise, resolve } }
const trash = entry => ({ ...entry, state_version: entry.state_version + 1, deleted_at: new Date().toISOString() })
const active = entry => ({ ...entry, state_version: entry.state_version + 1, deleted_at: null })

test('account transport accepts combined Trash pagination and lifecycle routes without permitting arbitrary query strings', async (t) => {
  const calls = []
  const removed = trash(fixture.entry)
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options })
    if (url.endsWith('/auth/session/')) return Response.json({ user: { id: 1, username: 'test' }, csrfToken: 'a'.repeat(64) })
    if (url.includes('?')) return Response.json({ count: 1, results: [removed], next: null })
    if (url.endsWith('/restore/')) return Response.json(active(removed))
    if (url.endsWith('/purge/')) return new Response(null, { status: 204 })
    return Response.json(removed)
  })
  const account = createAccountApi('/api')
  const api = createVaultApi(account.vaultRequest)
  assert.equal((await api.entries(fixture.vault.id, signal()))[0].deleted_at, removed.deleted_at)
  assert.equal(calls[0].url, `/api/vaults/${fixture.vault.id}/entries/?state=all&offset=0`)
  await api.remove(fixture.entry, signal())
  await api.restoreEntry(removed, signal())
  await api.purge(removed, signal())
  assert.ok(calls.filter(call => call.options.method !== 'GET').every(call => call.options.headers['X-CSRFToken'] === 'a'.repeat(64)))
  const previous = calls.length
  for (const path of ['https://untrusted.example', 'vaults?state=all&page=1&next=https://untrusted.example', 'vaults?page=0', 'vaults?state=trash&page=1', 'vaults?state=all&page=1#fragment']) {
    await assert.rejects(account.vaultRequest(path), /Invalid API path/)
  }
  assert.equal(calls.length, previous)
})

function memoryApi(records = [fixture.entry]) {
  let rows = structuredClone(records)
  const calls = []
  function current(entry, deleted) {
    const row = rows.find(row => row.id === entry.id)
    if (!row || row.revision !== entry.revision || row.state_version !== entry.state_version || (row.deleted_at !== null) !== deleted) throw new ApiError('State changed.', 409)
    return row
  }
  const api = {
    vaults: async () => [fixture.vault],
    preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }),
    entries: async () => structuredClone(rows),
    remove: async entry => {
      calls.push('trash')
      const changed = trash(current(entry, false))
      rows = rows.map(row => row.id === entry.id ? changed : row)
      return structuredClone(changed)
    },
    restoreEntry: async entry => {
      calls.push('restore')
      const changed = active(current(entry, true))
      rows = rows.map(row => row.id === entry.id ? changed : row)
      return structuredClone(changed)
    },
    purge: async entry => {
      calls.push('purge')
      current(entry, true)
      rows = rows.filter(row => row.id !== entry.id)
    },
    save: async (vaultId, id, revision, encrypted, _signal, stateVersion) => {
      calls.push('save')
      const row = rows.find(row => row.id === id)
      if (!row || row.state_version !== stateVersion || row.deleted_at !== null) throw new ApiError('State changed.', 409)
      const changed = { ...row, ...encrypted, revision, vault_id: vaultId }
      rows = rows.map(row => row.id === id ? changed : row)
      return structuredClone(changed)
    },
    restoreReceipt: async () => null,
  }
  return { api, calls }
}

async function unlocked(api) {
  const controller = new VaultController(api, derive)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  assert.equal(await controller.unlock(fixture.master), true)
  return controller
}

test('Trash transport sends only both versions and validates unchanged authenticated ciphertext', async () => {
  const removed = trash(fixture.entry)
  const restored = active(removed)
  const calls = []
  const api = createVaultApi(async (...args) => {
    calls.push(args)
    return args[0].endsWith('/restore') ? restored : args[0].endsWith('/purge') ? null : removed
  })
  assert.deepEqual(await api.remove(fixture.entry, signal()), removed)
  assert.deepEqual(await api.restoreEntry(removed, signal()), restored)
  await api.purge(removed, signal())
  assert.deepEqual(calls.map(call => call[1]), ['DELETE', 'POST', 'DELETE'])
  assert.deepEqual(calls.map(call => call[2]), [
    { expected_revision: 1, expected_state_version: 1 },
    { expected_revision: 1, expected_state_version: 2 },
    { expected_revision: 1, expected_state_version: 2 },
  ])
  assert.ok(!JSON.stringify(calls).includes(fixture.payload.password))
  for (const changes of [{ revision: 2 }, { state_version: 1 }, { state_version: 3 }, { deleted_at: null }, { nonce: fixture.vault.wrap_nonce }, { id: crypto.randomUUID() }, { ciphertext: 'invalid' }]) {
    await assert.rejects(createVaultApi(async () => ({ ...removed, ...changes })).remove(fixture.entry, signal()))
  }
  await assert.rejects(createVaultApi(async () => removed).restoreEntry(removed, signal()))
})

test('transport rejects missing and malformed lifecycle metadata before decrypting', () => {
  for (const changes of [{ state_version: undefined }, { state_version: true }, { state_version: 0 }, { state_version: 2147483648 }, { deleted_at: undefined }, { deleted_at: '' }, { deleted_at: 42 }]) {
    assert.throws(() => validateEnvelope({ ...fixture.entry, ...changes }, fixture.vault.id))
  }
})

test('moving and restoring preserve exact plaintext and ciphertext while separating active health', async () => {
  const { api } = memoryApi()
  const controller = await unlocked(api)
  assert.equal(await controller.remove(fixture.entry.id, 1, 1), true)
  let snapshot = controller.getSnapshot()
  assert.deepEqual(snapshot.entries, [])
  assert.deepEqual(snapshot.trash[0].data, fixture.payload)
  assert.equal(snapshot.trash[0].envelope.state_version, 2)
  assert.equal(snapshot.trash[0].envelope.ciphertext, fixture.entry.ciphertext)
  assert.equal(analyzePasswords(snapshot.entries).total, 0)
  assert.equal(await controller.restoreEntry(fixture.entry.id, 1, 2), true)
  snapshot = controller.getSnapshot()
  assert.deepEqual(snapshot.trash, [])
  assert.deepEqual(snapshot.entries[0].data, fixture.payload)
  assert.equal(snapshot.entries[0].envelope.state_version, 3)
  assert.equal(snapshot.entries[0].envelope.revision, 1)
  assert.equal(await controller.save({ ...fixture.payload, title: 'After restore' }, fixture.entry.id, 1, 3), true)
  const row = controller.getSnapshot().entries[0]
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  assert.equal((await decryptEntry(key, row.envelope)).title, 'After restore')
})

test('old editors and purge confirmations remain stale even after a delete and restore cycle', async () => {
  const { api, calls } = memoryApi()
  const controller = await unlocked(api)
  const deleted = await api.remove(fixture.entry)
  const restored = await api.restoreEntry(deleted)
  await controller.refresh()
  calls.length = 0
  assert.equal(await controller.save(fixture.payload, fixture.entry.id, 1, 1), false)
  assert.equal(await controller.remove(fixture.entry.id, 1, 1), false)
  assert.deepEqual(calls, [])
  assert.equal(controller.getSnapshot().unlocked, true)
  const deletedAgain = await api.remove(restored)
  const restoredAgain = await api.restoreEntry(deletedAgain)
  await api.remove(restoredAgain)
  await controller.refresh()
  calls.length = 0
  assert.equal(await controller.purge(fixture.entry.id, 1, deletedAgain.state_version), false)
  assert.equal(await controller.restoreEntry(fixture.entry.id, 1, deletedAgain.state_version), false)
  assert.deepEqual(calls, [])
  assert.equal(controller.getSnapshot().trash.length, 1)
})

test('unlock and backup refresh include Trash but exports exclude its plaintext records', async () => {
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const id = crypto.randomUUID()
  const second = { ...fixture.entry, id, ...await encryptEntry(key, fixture.vault.id, id, 1, { ...fixture.payload, title: 'Active only' }) }
  const { api } = memoryApi([trash(fixture.entry), second])
  const controller = await unlocked(api)
  assert.equal(controller.getSnapshot().entries.length, 1)
  assert.equal(controller.getSnapshot().trash.length, 1)
  const password = 'PUBLIC synthetic backup password 2026!'
  assert.equal(await controller.exportBackup(password), true)
  const archive = await openBackup(controller.getSnapshot().backupExport.text, password, derive, signal())
  assert.deepEqual(archive.content.entries.map(entry => entry.payload.title), ['Active only'])
  assert.equal(await controller.restoreEntry(fixture.entry.id, 1, 2), true)
  assert.equal(controller.getSnapshot().backupExport, null)
})

test('permanent deletion removes only Trash and locking clears both sets of plaintext', async () => {
  const { api } = memoryApi([trash(fixture.entry)])
  const controller = await unlocked(api)
  assert.equal(await controller.purge(fixture.entry.id, 1, 2), true)
  assert.deepEqual(controller.getSnapshot().trash, [])
  assert.deepEqual(await api.entries(), [])
  controller.lock()
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.deepEqual(controller.getSnapshot().trash, [])
  assert.ok(!JSON.stringify(controller.getSnapshot()).includes(fixture.payload.password))
})

test('late Trash writes cannot publish plaintext after lock or account switch', async () => {
  for (const operation of ['remove', 'restoreEntry', 'purge']) {
    const trashed = trash(fixture.entry)
    const { api } = memoryApi(operation === 'remove' ? [fixture.entry] : [trashed])
    const entered = deferred()
    const gate = deferred()
    api[operation] = async () => { entered.resolve(); await gate.promise; return operation === 'remove' ? trashed : active(trashed) }
    const controller = await unlocked(api)
    const pending = controller[operation](fixture.entry.id, 1, operation === 'remove' ? 1 : 2)
    await entered.promise
    controller.switchAccount(2, false)
    gate.resolve()
    assert.equal(await pending, false)
    assert.equal(controller.getSnapshot().ownerId, 2)
    assert.equal(controller.getSnapshot().unlocked, false)
    assert.deepEqual(controller.getSnapshot().entries, [])
    assert.deepEqual(controller.getSnapshot().trash, [])
    assert.ok(!JSON.stringify(controller.getSnapshot()).includes(fixture.payload.password))
  }
})

test('a corrupt Trash record fails unlock without returning active plaintext', async () => {
  const { api } = memoryApi([fixture.entry, { ...trash(fixture.entry), id: crypto.randomUUID() }])
  const controller = new VaultController(api, derive)
  controller.switchAccount(1, false)
  await controller.load()
  assert.equal(await controller.unlock(fixture.master), false)
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.deepEqual(controller.getSnapshot().trash, [])
})
