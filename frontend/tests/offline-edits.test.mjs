import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { ApiError } from '../src/api.ts'
import { VaultController } from '../src/vault/controller.ts'
import { encryptEntry, importDataKey } from '../src/vault/crypto.ts'
import { pendingWriteId } from '../src/vault/outbox.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const { id: vaultId } = fixture.vault
const { id: entryId } = fixture.entry
const draft = { ...fixture.payload, title: 'Local draft title', password: 'Local draft password' }
const derive = async (password) => password === fixture.master
  ? new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex')) : new Uint8Array(32).fill(99)

function setup() {
  const rows = new Map()
  const outbox = {
    list: async (owner, vault) => [...rows].filter(([key]) => key.startsWith(`${owner}:${vault}:`)).map(([, value]) => value),
    change: async (owner, vault, before, after) => {
      const key = (write) => `${owner}:${vault}:${write.envelope.id}`
      const previous = before && rows.get(key(before))
      if (before && (!previous || pendingWriteId(previous) !== pendingWriteId(before))) return false
      if (after && rows.has(key(after))) return false
      if (before) rows.delete(key(before))
      if (after) rows.set(key(after), structuredClone(after))
      return true
    },
  }
  const entries = new Map([[entryId, fixture.entry]])
  const state = { offline: false, entriesOffline: false, loseResponse: false, writes: 0, trashWrites: 0, purgeWrites: 0,
    keyVersion: 1, unauthorized: false, metadata: fixture.vault }
  let version = crypto.randomUUID()
  function checkNetwork() {
    if (state.unauthorized) throw new ApiError('Sign in again.', 403)
    if (state.offline) throw new TypeError('Network disconnected')
  }
  function transition(entry, deleted) {
    checkNetwork()
    const previous = entries.get(entry.id)
    if (previous?.revision !== entry.revision || previous.state_version !== entry.state_version || Boolean(previous.deleted_at) === deleted) {
      throw new ApiError('State changed', 409)
    }
    const envelope = { ...previous, state_version: previous.state_version + 1, deleted_at: deleted ? new Date().toISOString() : null }
    entries.set(entry.id, envelope)
    version = crypto.randomUUID()
    state.trashWrites += 1
    if (state.loseResponse) throw new TypeError('Lost response after commit')
    return envelope
  }
  const api = {
    vaults: async () => { checkNetwork(); return [{ ...state.metadata, key_version: state.keyVersion }] },
    preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }),
    entries: async (_vault, _signal, report) => {
      checkNetwork()
      if (state.entriesOffline) throw new TypeError('Entry endpoint disconnected')
      report(version)
      return [...entries.values()]
    },
    entriesVersion: async () => { checkNetwork(); return version },
    entry: async (_vault, id) => { checkNetwork(); return entries.get(id) ?? null },
    remove: async (entry) => transition(entry, true),
    restoreEntry: async (entry) => transition(entry, false),
    purge: async (entry) => {
      checkNetwork()
      assert.ok(entries.get(entry.id)?.deleted_at)
      entries.delete(entry.id)
      state.purgeWrites += 1
    },
    save: async (_vault, id, revision, encrypted, _signal, stateVersion, keyVersion) => {
      checkNetwork()
      assert.equal(keyVersion, state.keyVersion)
      const previous = entries.get(id)
      if (revision === 1 ? previous : previous?.revision !== revision - 1 || previous.state_version !== stateVersion || previous.deleted_at) {
        throw new ApiError('Version conflict', 409)
      }
      state.writes += 1
      const envelope = { ...fixture.entry, id, revision, state_version: stateVersion, nonce: encrypted.nonce, ciphertext: encrypted.ciphertext }
      entries.set(id, envelope)
      version = crypto.randomUUID()
      if (state.loseResponse) throw new TypeError('Lost response after commit')
      return envelope
    },
  }
  return { outbox, state, entries, changeRemote: (envelope) => {
    entries.set(envelope.id, envelope)
    version = crypto.randomUUID()
  }, open: async (owner = 1, clock = Date.now) => {
    const controller = new VaultController(api, derive, clock, outbox)
    controller.switchAccount(owner, false)
    assert.equal(await controller.load(), true)
    assert.equal(await controller.unlock(fixture.master), true)
    return controller
  } }
}

test('offline edits commit ciphertext locally and sync after reopening in the same browser', async () => {
  const { state, outbox, open } = setup()
  const controller = await open()
  state.offline = true
  assert.equal(await controller.save(draft, entryId, 1, 1), true)
  assert.equal(controller.getSnapshot().pending[0].data.title, draft.title)
  assert.equal(await controller.save({ ...draft, title: 'Second edit' }, entryId, 1, 1), false)
  assert.equal(await controller.refresh(), false)
  assert.equal(controller.getSnapshot().unlocked, true)
  const serialized = JSON.stringify(await outbox.list(1, vaultId))
  assert.equal(serialized.includes(draft.title), false)
  assert.equal(serialized.includes(draft.password), false)
  controller.lock()
  assert.deepEqual(controller.getSnapshot().pending, [])
  state.offline = false
  assert.deepEqual((await open(2)).getSnapshot().pending, [])
  const reopened = await open()
  await reopened.sync()
  assert.equal(state.writes, 1)
  assert.equal(reopened.getSnapshot().entries[0].data.title, draft.title)
  assert.deepEqual(await outbox.list(1, vaultId), [])
})

test('a lost save response acknowledges the same ciphertext without replaying a committed write', async () => {
  const { state, outbox, open } = setup()
  const controller = await open()
  state.loseResponse = true
  assert.equal(await controller.save(draft), true)
  assert.equal(controller.getSnapshot().pending.length, 1)
  state.loseResponse = false
  await controller.sync()
  assert.equal(state.writes, 1)
  assert.equal(controller.getSnapshot().entries.length, 2)
  assert.deepEqual(await outbox.list(1, vaultId), [])
})

test('a remote edit preserves both versions and creates a copy only after the user chooses it', async () => {
  const { state, open, entries, changeRemote } = setup()
  const controller = await open()
  state.offline = true
  assert.equal(await controller.save(draft, entryId, 1, 1), true)
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const remote = { ...fixture.payload, title: 'Server edit' }
  changeRemote({ ...fixture.entry, revision: 2, ...await encryptEntry(key, vaultId, entryId, 2, remote) })
  state.offline = false
  await controller.sync()
  assert.equal(state.writes, 0)
  const { pending, entries: displayed } = controller.getSnapshot()
  assert.equal(displayed[0].data.title, remote.title)
  assert.equal(pending[0].status, 'conflict')
  assert.equal(await controller.resolvePending(pending[0].write.envelope.nonce, true), true)
  await controller.sync()
  await controller.sync()
  assert.equal(state.writes, 1)
  assert.equal(entries.get(entryId).revision, 2)
  assert.deepEqual(controller.getSnapshot().entries.map(({ data }) => data.title).sort(), [draft.title, remote.title].sort())
})

test('Trash state changes are conflicts and confirmed auth loss clears local plaintext', async () => {
  const { state, outbox, open, changeRemote } = setup()
  const controller = await open()
  state.offline = true
  await controller.save(draft, entryId, 1, 1)
  changeRemote({ ...fixture.entry, deleted_at: new Date().toISOString(), state_version: 2 })
  state.offline = false
  await controller.sync()
  assert.equal(controller.getSnapshot().pending[0].status, 'conflict')
  assert.equal(controller.getSnapshot().trash[0].envelope.id, entryId)
  state.unauthorized = true
  await controller.sync()
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().pending, [])
  assert.equal((await outbox.list(1, vaultId)).length, 1)
  assert.equal(state.writes, 0)
})

test('auto-lock clears plaintext and the same tab can unlock and edit while disconnected', async () => {
  let now = 1000
  const { state, open } = setup()
  const controller = await open(1, () => now)
  state.offline = true
  now += 300_000
  controller.checkIdle()
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.deepEqual(controller.getSnapshot().entries, [])
  assert.equal(controller.getSnapshot().offlineReady, true)
  assert.equal(await controller.unlock('Incorrect master password'), false)
  assert.equal(await controller.unlock(fixture.master), true)
  assert.equal(controller.getSnapshot().offlineUnlocked, true)
  assert.equal(controller.getSnapshot().entries[0].data.title, fixture.payload.title)

  state.offline = false
  assert.equal(await controller.save(draft, entryId, 1, 1), true)
  assert.equal(state.writes, 0)
  assert.equal(await controller.purge(entryId, 1, 1), false)
  assert.match(controller.getSnapshot().error, /Reconnect and sync/)
  await controller.sync()
  assert.equal(controller.getSnapshot().offlineUnlocked, false)
  assert.equal(controller.getSnapshot().entries[0].data.title, draft.title)
  assert.equal(state.writes, 1)
})

test('confirmed loss of access locks an offline vault before replay and removes the cached snapshot', async () => {
  const { state, open, outbox } = setup()
  const controller = await open()
  controller.lock()
  state.offline = true
  assert.equal(await controller.unlock(fixture.master), true)
  assert.equal(await controller.save(draft, entryId, 1, 1), true)
  state.offline = false
  state.unauthorized = true
  await controller.sync()
  assert.equal(controller.getSnapshot().offlineReady, false)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.equal((await outbox.list(1, vaultId)).length, 1)
  assert.equal(state.writes, 0)

  state.unauthorized = false
  state.offline = true
  assert.equal(await controller.unlock(fixture.master), false)
})

test('a changed master-password wrapper invalidates the cached snapshot while locked or offline unlocked', async () => {
  for (const reconnectUnlocked of [false, true]) {
    const { state, open } = setup()
    const controller = await open()
    controller.lock()
    if (reconnectUnlocked) {
      state.offline = true
      assert.equal(await controller.unlock(fixture.master), true)
      state.offline = false
    }
    state.metadata = { ...fixture.vault, wrap_nonce: btoa('new-12-bytes') }
    if (reconnectUnlocked) assert.equal(await controller.refresh(), false)
    else await controller.sync()
    assert.equal(controller.getSnapshot().offlineReady, false)
    assert.equal(controller.getSnapshot().unlocked, false)
    state.offline = true
    assert.equal(await controller.unlock(fixture.master), false)
  }
})

test('a partial outage can use cached entries but a forgotten snapshot cannot be reopened', async () => {
  const { state, open } = setup()
  const controller = await open()
  controller.lock()
  state.entriesOffline = true
  assert.equal(await controller.unlock(fixture.master), true)
  assert.equal(controller.getSnapshot().offlineUnlocked, true)
  controller.forgetOffline()
  assert.equal(controller.getSnapshot().offlineReady, false)
  assert.equal(await controller.unlock(fixture.master), false)
})

test('offline move and restore survive reopen and preserve authenticated content', async () => {
  const { state, outbox, open } = setup()
  const controller = await open()
  controller.lock()
  state.offline = true
  assert.equal(await controller.unlock(fixture.master), true)
  assert.equal(await controller.remove(entryId, 1, 1), true)
  assert.equal(controller.getSnapshot().entries.length, 1)
  assert.equal(await controller.save(draft, entryId, 1, 1), false)
  const [move] = await outbox.list(1, vaultId)
  assert.equal(move.kind, 'move')
  assert.equal(move.envelope.ciphertext, fixture.entry.ciphertext)
  assert.ok(!JSON.stringify(move).includes(fixture.payload.password))
  controller.lock()
  state.offline = false
  const reopened = await open()
  await reopened.sync()
  assert.equal(reopened.getSnapshot().entries.length, 0)
  assert.equal(reopened.getSnapshot().trash[0].envelope.state_version, 2)
  state.offline = true
  assert.equal(await reopened.restoreEntry(entryId, 1, 2), true)
  assert.equal(reopened.getSnapshot().trash.length, 1)
  const [restore] = await outbox.list(1, vaultId)
  assert.equal(restore.kind, 'restore')
  assert.equal(restore.envelope.nonce, move.envelope.nonce)
  assert.notEqual(pendingWriteId(restore), pendingWriteId(move))
  state.offline = false
  assert.equal(await reopened.refresh(), true)
  assert.equal(state.trashWrites, 2)
  assert.deepEqual(reopened.getSnapshot().entries[0].data, fixture.payload)
  assert.equal(reopened.getSnapshot().entries[0].envelope.state_version, 3)
  assert.deepEqual(await outbox.list(1, vaultId), [])
})

test('a lost Trash response confirms the exact resulting state without writing again', async () => {
  const { state, open, outbox } = setup()
  const controller = await open()
  state.loseResponse = true
  assert.equal(await controller.remove(entryId, 1, 1), true)
  assert.equal(controller.getSnapshot().pending.length, 1)
  await controller.sync()
  assert.equal(controller.getSnapshot().trash[0].envelope.state_version, 2)
  assert.equal(await controller.restoreEntry(entryId, 1, 2), true)
  await controller.sync()
  assert.equal(controller.getSnapshot().entries[0].envelope.state_version, 3)
  assert.equal(state.trashWrites, 2)
  assert.deepEqual(await outbox.list(1, vaultId), [])
})

test('a queued restore cannot override a newer Trash cycle or become a duplicate entry', async () => {
  const { state, open, changeRemote } = setup()
  const initial = { ...fixture.entry, deleted_at: '2026-01-01T00:00:00Z', state_version: 2 }
  changeRemote(initial)
  const controller = await open()
  state.offline = true
  assert.equal(await controller.restoreEntry(entryId, 1, 2), true)
  changeRemote({ ...initial, state_version: 4 })
  state.offline = false
  await controller.sync()
  const [pending] = controller.getSnapshot().pending
  assert.equal(pending.status, 'conflict')
  assert.equal(await controller.resolvePending(pendingWriteId(pending.write), true), false)
  assert.equal(await controller.resolvePending(pendingWriteId(pending.write), false), true)
  assert.equal(state.trashWrites, 0)
  assert.equal(state.writes, 0)
  assert.equal(controller.getSnapshot().trash[0].envelope.state_version, 4)
})

test('permanent deletion requires the server and respects a pending restore from another tab', async () => {
  const { state, open, outbox, changeRemote } = setup()
  changeRemote({ ...fixture.entry, deleted_at: '2026-01-01T00:00:00Z', state_version: 2 })
  const first = await open()
  const second = await open()
  state.offline = true
  assert.equal(await second.purge(entryId, 1, 2), false)
  assert.deepEqual(await outbox.list(1, vaultId), [])
  assert.equal(await first.restoreEntry(entryId, 1, 2), true)
  state.offline = false
  assert.equal(second.getSnapshot().pending.length, 0)
  assert.equal(await second.purge(entryId, 1, 2), false)
  assert.match(second.getSnapshot().error, /local change/)
  assert.equal(state.purgeWrites, 0)
})
