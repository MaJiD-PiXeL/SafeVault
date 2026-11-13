import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createVaultApi } from '../src/vault/api.ts'
import { ApiError } from '../src/api.ts'
const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))

test('vault writes select only transport fields and include optimistic revisions', async () => {
  const calls = []
  const api = createVaultApi(async (...args) => {
    calls.push(args)
    if (args[0] === 'vaults') return fixture.vault
    if (args[1] === 'DELETE') return { ...fixture.entry, state_version: 2, deleted_at: new Date().toISOString() }
    return { ...fixture.entry, revision: args[1] === 'PATCH' ? 2 : 1 }
  })
  const signal = new AbortController().signal
  await api.create({ ...fixture.vault, master_password: 'must not leave client' }, signal)
  assert.ok(!JSON.stringify(calls).includes('must not leave client'))
  await api.save(fixture.vault.id, fixture.entry.id, 1, { ...fixture.entry, password: 'must not leave client' }, signal)
  assert.deepEqual(Object.keys(calls[1][2]).sort(), ['ciphertext', 'id', 'nonce'])
  await api.save(fixture.vault.id, fixture.entry.id, 2, fixture.entry, signal)
  assert.equal(calls[2][2].expected_revision, 1)
  await api.remove(fixture.entry, signal)
  assert.deepEqual(calls[3][2], { expected_revision: 1, expected_state_version: 1 })
})

test('entry pagination constructs local routes instead of following server-supplied links', async () => {
  const paths = []
  const second = { ...fixture.entry, id: crypto.randomUUID() }
  const api = createVaultApi(async (path) => {
    paths.push(path)
    return paths.length === 1 ? { count: 2, results: [fixture.entry], next: 'https://untrusted.example/steal' }
      : { count: 2, results: [second], next: null }
  })
  assert.equal((await api.entries(fixture.vault.id, new AbortController().signal)).length, 2)
  const base = `vaults/${fixture.vault.id}/entries?state=all`
  assert.deepEqual(paths, [`${base}&offset=0`, `${base}&page=2`])
})

test('bounded pagination advances by the actual batch size and validates continuation and version', async () => {
  const second = { ...fixture.entry, id: crypto.randomUUID() }
  const version = crypto.randomUUID()
  const base = `vaults/${fixture.vault.id}/entries?state=all&offset=`
  const signal = new AbortController().signal
  const calls = []
  const first = { version, count: 2, next_offset: 1, results: [fixture.entry] }
  const last = { version, count: 2, next_offset: null, results: [second] }
  let reported
  const api = createVaultApi(async (path) => {
    calls.push(path)
    return path === base + '0' ? first : last
  })
  assert.deepEqual(await api.entries(fixture.vault.id, signal, (value) => { reported = value }), [fixture.entry, second])
  assert.deepEqual(calls, [base + '0', base + '1'])
  assert.equal(reported, version)
  for (const malformed of [{ ...first, next_offset: 0 }, { ...first, next_offset: 2 },
    { ...first, next_offset: '1' }, { ...first, results: [] }, { ...first, version: undefined }]) {
    await assert.rejects(createVaultApi(async () => malformed).entries(fixture.vault.id, signal), { name: 'VaultDataError' })
  }
  const racing = createVaultApi(async (path) => path === base + '0' ? first : { ...last, version: crypto.randomUUID() })
  await assert.rejects(racing.entries(fixture.vault.id, signal), (error) => error.status === 409)
})

test('pagination detects incomplete snapshots, duplicates, wrong vaults and allocation limits', async () => {
  for (const response of [
    { count: 2, results: [fixture.entry], next: null },
    { count: 2, results: [fixture.entry, fixture.entry], next: null },
    { count: 1, results: [{ ...fixture.entry, vault_id: crypto.randomUUID() }], next: null },
    { count: 5001, results: [], next: null },
  ]) await assert.rejects(createVaultApi(async () => response).entries(fixture.vault.id, new AbortController().signal))
})

test('unsupported security preferences and changed creation envelopes are rejected', async () => {
  const signal = new AbortController().signal
  await assert.rejects(createVaultApi(async () => ({ auto_lock_seconds: 0, lock_on_hidden: false })).preferences(signal))
  await assert.rejects(createVaultApi(async () => ({ ...fixture.vault, id: crypto.randomUUID() })).create(fixture.vault, signal))
})

test('restore sends only newly encrypted envelopes and validates its commit receipt', async () => {
  const id = crypto.randomUUID()
  const calls = []
  const api = createVaultApi(async (...args) => {
    calls.push(args)
    return { backup_id: id, archive_digest: 'a'.repeat(64), entry_count: 1, already_restored: false }
  })
  const signal = new AbortController().signal
  await api.restore(fixture.vault.id, id, 'a'.repeat(64), [{ ...fixture.entry, password: 'must not leave client' }], signal)
  assert.equal(calls[0][4], 60000)
  assert.deepEqual(Object.keys(calls[0][2]).sort(), ['archive_digest', 'backup_id', 'entries'])
  assert.deepEqual(Object.keys(calls[0][2].entries[0]).sort(), ['ciphertext', 'id', 'nonce'])
  assert.ok(!JSON.stringify(calls).includes('must not leave client'))
  assert.equal(await createVaultApi(async () => { throw new ApiError('missing', 404) }).restoreReceipt(fixture.vault.id, id, signal), null)
  await assert.rejects(createVaultApi(async () => { throw new ApiError('denied', 403) }).restoreReceipt(fixture.vault.id, id, signal))
})
