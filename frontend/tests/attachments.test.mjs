import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { attachmentBlob, readAttachments } from '../src/vault/attachments.ts'
import { createBackup, openBackup } from '../src/vault/backup.ts'
import { decryptEntry, encryptEntry, importDataKey, prepareKeyRotation, unlockEncryptedVault } from '../src/vault/crypto.ts'
import { decodeEntryPayload, encodeEntryPayload, fromBase64, MAX_ATTACHMENT_BYTES, validAttachmentName, validateEnvelope } from '../src/vault/format.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const signal = () => new AbortController().signal
const derive = async (password, salt) => password === fixture.master && Buffer.from(salt).toString('base64') === fixture.vault.kdf_salt
  ? Buffer.from(fixture.wrapping_key_hex, 'hex') : createHash('sha256').update(password).update(salt).digest()

test('attachment payload keeps binary bytes and filenames encrypted through backup and key rotation', async () => {
  const original = new Uint8Array(MAX_ATTACHMENT_BYTES).map((_, i) => i % 251)
  const filename = 'یادداشت خصوصی.html'
  const attachments = await readAttachments([new File([original], filename, { type: 'text/html' })], [], signal())
  const note = { schema_version: 2, kind: 'note', title: 'Synthetic note', notes: 'Private text', category: '', favorite: false }
  const data = { ...note, attachments }
  assert.deepEqual(encodeEntryPayload(note), note)
  assert.deepEqual(encodeEntryPayload(data), { schema_version: 3, record: note, attachments })
  const key = await importDataKey(Buffer.from(fixture.data_key_hex, 'hex'))
  const { vault, entry } = fixture
  const encrypted = validateEnvelope({ ...entry, ...await encryptEntry(key, vault.id, entry.id, 1, data) }, vault.id)
  assert.ok(encrypted.ciphertext.length > 128 * 1024)
  for (const value of [filename, attachments[0].content]) assert.ok(!JSON.stringify(encrypted).includes(value))
  assert.deepEqual(await decryptEntry(key, encrypted), data)

  const backupPassword = 'Synthetic backup phrase 01!'
  const backup = await createBackup(vault.id, [{ envelope: encrypted, data }], backupPassword, derive, signal())
  assert.ok(!backup.includes(filename))
  const restored = (await openBackup(backup, backupPassword, derive, signal())).content.entries[0].payload
  assert.deepEqual(restored, data)
  const downloaded = attachmentBlob(restored.attachments[0])
  assert.equal(downloaded.type, 'application/octet-stream')
  assert.deepEqual(new Uint8Array(await downloaded.arrayBuffer()), original)

  const next = 'Synthetic rotated phrase 02!'
  const rotated = await prepareKeyRotation(vault, [encrypted], fixture.master, next, derive, signal())
  const newKey = await unlockEncryptedVault(rotated.vault, next, derive, signal())
  assert.deepEqual(await decryptEntry(newKey, { ...encrypted, ...rotated.entries[0] }), data)
})

test('malformed or over-budget attachments fail before persistence', async () => {
  for (const name of ['../a.txt', 'a\\b.txt', 'NUL.pdf', 'x\u202ey.txt', 'end.', ' ']) assert.equal(validAttachmentName(name), false)
  const file = { name: 'small.txt', size: 1, content: 'AA==' }
  const wire = { schema_version: 3, record: fixture.payload, attachments: [file] }
  assert.deepEqual(decodeEntryPayload(wire), { ...fixture.payload, attachments: [file] })
  for (const content of ['AB==', 'AA=\n', 'AA', 'AAAA']) assert.throws(() => decodeEntryPayload({ ...wire, attachments: [{ ...file, content }] }))
  for (const bad of [{ ...wire, attachments: [] }, { ...wire, attachments: Array(4).fill(file) },
    { ...wire, record: { ...fixture.payload, attachments: [file] } }, { ...fixture.payload, attachments: [file] }]) {
    assert.throws(() => decodeEntryPayload(bad))
  }
  assert.deepEqual(fromBase64('AAAA', 3), new Uint8Array(3))
  let reads = 0
  const sized = (size) => ({ name: 'x.txt', size, arrayBuffer: async () => { reads += 1; return new ArrayBuffer(size) } })
  await assert.rejects(readAttachments([sized(MAX_ATTACHMENT_BYTES + 1)], [], signal()), /at most 1 MiB/)
  await assert.rejects(readAttachments([sized(MAX_ATTACHMENT_BYTES), sized(MAX_ATTACHMENT_BYTES), sized(1)], [], signal()), /2 MiB/)
  assert.equal(reads, 0)
})

test('aborting a local file read returns no attachment and clears the read bytes', async () => {
  let release
  const data = new Uint8Array([11, 22, 33])
  const abort = new AbortController()
  const file = { name: 'cancel.txt', size: data.length, arrayBuffer: () => new Promise((resolve) => { release = resolve }) }
  const read = readAttachments([file], [], abort.signal)
  abort.abort()
  release(data.buffer)
  await assert.rejects(read, { name: 'AbortError' })
  assert.deepEqual(data, new Uint8Array(3))
})
