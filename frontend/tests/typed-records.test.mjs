import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createBackup, openBackup } from '../src/vault/backup.ts'
import { decryptEntry, encryptEntry, importDataKey } from '../src/vault/crypto.ts'
import { entrySummary, validatePayload } from '../src/vault/format.ts'
import { analyzePasswords } from '../src/vault/health.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const note = { schema_version: 2, kind: 'note', title: 'Test note', notes: ' First line\nیادداشت  ', category: 'Test', favorite: true }
const card = { schema_version: 2, kind: 'card', title: 'Test payment card', notes: '', category: '', favorite: false,
  cardholder: 'Test Holder', card_number: '4242424242424242', expiry: '01/2030' }
const derive = async () => new Uint8Array(32).fill(24)

test('mixed records encrypt, decrypt and survive an encrypted backup with all fields', async () => {
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const entries = []
  for (const payload of [fixture.payload, note, card]) {
    const id = crypto.randomUUID()
    const encrypted = await encryptEntry(key, fixture.vault.id, id, 1, payload)
    const envelope = { ...fixture.entry, ...encrypted, id }
    const data = await decryptEntry(key, envelope)
    assert.deepEqual(data, payload)
    entries.push({ envelope, data })
  }
  const password = 'Public fixture backup passphrase'
  const signal = new AbortController().signal
  const archive = await createBackup(fixture.vault.id, entries, password, derive, signal)
  assert.ok(!archive.includes(card.card_number) && !archive.includes(note.title))
  const opened = await openBackup(archive, password, derive, signal)
  assert.deepEqual(opened.content.entries.map(({ payload }) => payload), [fixture.payload, note, card])
  assert.equal(analyzePasswords(entries).total, 1)
  assert.equal(entrySummary(card).secondary, '•••• 4242')
})

test('typed payloads reject malformed and ambiguous records', () => {
  for (const value of [
    { ...note, notes: ' ' }, { ...note, password: 'unexpected' }, { ...note, kind: 'unknown' },
    { ...card, card_number: '12 34' }, { ...card, card_number: 4242424242424242 },
    { ...card, expiry: '14/2030' }, { ...card, cvv: '123' }, { ...fixture.payload, kind: 'note' },
  ]) assert.throws(() => validatePayload(value))
})
