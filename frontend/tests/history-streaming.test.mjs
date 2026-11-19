import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createHistoryGuard } from '../src/vault/history.ts'
import { createVaultApi } from '../src/vault/api.ts'
import { encryptEntry, importDataKey } from '../src/vault/crypto.ts'
import { VaultController } from '../src/vault/controller.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const signal = () => new AbortController().signal
const version = 'cf8c4b4e-4b01-4f4e-a334-0862e9174197'
const derive = async () => new Uint8Array(Buffer.from(fixture.wrapping_key_hex, 'hex'))
function guard() {
  const data = new Map()
  return { data, history: createHistoryGuard({ getItem: key => data.get(key) ?? null, setItem: (key, value) => data.set(key, value) }) }
}

test('history rejects older content, same-revision substitution and purged record resurrection', async () => {
  const { history } = guard()
  const { vault, entry } = fixture
  await history.observe(1, vault, [{ ...entry, revision: 2, state_version: 3 }], signal())
  await assert.rejects(history.observe(1, vault, [entry], signal()), /older or inconsistent/)
  await assert.rejects(history.observe(1, vault, [{ ...entry, revision: 2, state_version: 3, ciphertext: Buffer.alloc(48, 9).toString('base64') }], signal()), /older or inconsistent/)
  await history.observe(1, vault, [], signal(), [entry.id])
  await assert.rejects(history.observe(1, vault, [{ ...entry, revision: 5, state_version: 6 }], signal()), /older or inconsistent/)
  await history.observe(2, vault, [entry], signal())
})

test('fresh wrappers and encryption rotations are accepted while previous wrappers and keys are rejected', async () => {
  const { history } = guard()
  const changed = { ...fixture.vault, wrap_nonce: Buffer.alloc(12, 6).toString('base64') }
  await history.observe(1, fixture.vault, [fixture.entry], signal())
  await history.observe(1, changed, [fixture.entry], signal())
  await assert.rejects(history.observe(1, fixture.vault, [fixture.entry], signal()), /older or inconsistent/)
  const rotated = { ...changed, key_version: 2 }
  const entry = { ...fixture.entry, ciphertext: Buffer.alloc(48, 8).toString('base64') }
  await history.observe(1, rotated, [], signal())
  await history.observe(1, rotated, [entry], signal())
  await history.observe(1, rotated, [entry], signal())
  await assert.rejects(history.observe(1, changed, [fixture.entry], signal()), /older or inconsistent/)
})

test('corrupt browser history and failed storage do not silently reset protection', async () => {
  const { history, data } = guard()
  await history.observe(1, fixture.vault, [fixture.entry], signal())
  data.set([...data.keys()][0], '{broken')
  await assert.rejects(history.observe(1, fixture.vault, [fixture.entry], signal()), /damaged/)
  const unavailable = createHistoryGuard({ getItem: () => null, setItem: () => { throw new Error('quota') } })
  await assert.rejects(unavailable.observe(1, fixture.vault, [fixture.entry], signal()), /could not save/)
})

test('partial write observations preserve records another tab already observed', async () => {
  const { history } = guard()
  const other = { ...fixture.entry, id: '225830f6-22d3-4f14-a3f0-b211f7db698d' }
  await history.observe(1, fixture.vault, [fixture.entry, other], signal())
  await history.observe(1, fixture.vault, [fixture.entry], signal())
  await history.observe(1, fixture.vault, [fixture.entry, other], signal())
})

test('rotation rejects an authenticated older snapshot before submitting a new key', async () => {
  const { history } = guard()
  const key = await importDataKey(new Uint8Array(Buffer.from(fixture.data_key_hex, 'hex')))
  const latest = { ...fixture.entry, revision: 2, ...await encryptEntry(key, fixture.vault.id, fixture.entry.id, 2, fixture.payload) }
  let stale = false
  let rotations = 0
  const controller = new VaultController({
    vaults: async () => [fixture.vault], preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }),
    entries: async (_id, _signal, onVersion) => { onVersion(version); return [stale ? fixture.entry : latest] },
    rotateKey: async () => { rotations += 1; throw new Error('must not submit') },
  }, derive, Date.now, undefined, history)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  assert.equal(await controller.unlock(fixture.master), true)
  stale = true
  assert.equal(await controller.rotateKey(fixture.master, 'PUBLIC replacement master phrase 17!'), false)
  assert.equal(rotations, 0)
  assert.equal(controller.getSnapshot().unlocked, false)
  assert.match(controller.getSnapshot().error, /older or inconsistent/)
})

test('pagination awaits each consumer and returns no second materialized ciphertext list', async () => {
  const second = { ...fixture.entry, id: '225830f6-22d3-4f14-a3f0-b211f7db698d' }
  const seen = []
  const api = createVaultApi(async path => {
    if (path.endsWith('offset=0')) return { count: 2, results: [fixture.entry], next_offset: 1, version }
    assert.deepEqual(seen, [fixture.entry.id])
    return { count: 2, results: [second], next_offset: null, version }
  })
  let resultVersion
  const result = await api.entries(fixture.vault.id, signal(), value => { resultVersion = value }, 1,
    async batch => { await Promise.resolve(); seen.push(...batch.map(item => item.id)) })
  assert.deepEqual(result, [])
  assert.equal(seen.length, 2)
  assert.equal(resultVersion, version)
})

test('a corrupt later page publishes no partial plaintext during a streamed unlock', async () => {
  const key = await importDataKey(new Uint8Array(Buffer.from(fixture.data_key_hex, 'hex')))
  const id = '225830f6-22d3-4f14-a3f0-b211f7db698d'
  const encrypted = await encryptEntry(key, fixture.vault.id, id, 1, fixture.payload)
  const bad = { ...fixture.entry, id, ...encrypted, ciphertext: Buffer.alloc(48).toString('base64') }
  const api = createVaultApi(async path => {
    if (path === 'vaults') return { vaults: [fixture.vault] }
    if (path === 'security-settings') return { auto_lock_seconds: 300, lock_on_hidden: true }
    return path.endsWith('offset=0') ? { count: 2, results: [fixture.entry], next_offset: 1, version } :
      { count: 2, results: [bad], next_offset: null, version }
  })
  const controller = new VaultController({ ...api, preferences: async () => ({ auto_lock_seconds: 300, lock_on_hidden: true }) }, derive)
  controller.switchAccount(1, false)
  assert.equal(await controller.load(), true)
  const snapshots = []
  controller.subscribe(() => snapshots.push(controller.getSnapshot()))
  assert.equal(await controller.unlock(fixture.master), false)
  assert.ok(snapshots.every(snapshot => !snapshot.unlocked && snapshot.entries.length === 0))
})
