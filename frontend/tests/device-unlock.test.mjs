import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { saveDeviceUnlock, openDeviceUnlock, hasDeviceUnlock, forgetDeviceUnlock } from '../src/vault/device.ts'
import { decryptEntry } from '../src/vault/crypto.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const signal = () => new AbortController().signal

function environment(t) {
  const store = new Map()
  property(t, globalThis, 'localStorage', { value: { getItem: key => store.get(key) ?? null,
    setItem: (key, value) => store.set(key, value), removeItem: key => store.delete(key) }, configurable: true })
  property(t, globalThis, 'location', { value: { origin: 'https://vault.example.com' }, configurable: true })
  property(t, globalThis, 'PublicKeyCredential', { value: class {}, configurable: true })
  const calls = []
  let bytes = new Uint8Array(32).fill(41)
  const credentials = {
    create: async options => { calls.push(options); return { rawId: new Uint8Array(32).fill(7).buffer,
      getClientExtensionResults: () => ({ prf: { enabled: true } }) } },
    get: async options => { calls.push(options); return { getClientExtensionResults: () => ({ prf: { results: { first: bytes.slice().buffer } } }) } },
  }
  property(t, navigator, 'credentials', { value: credentials, configurable: true })
  return { store, calls, credentials, changeSecret: () => { bytes = new Uint8Array(32).fill(42) } }
}

test('device PRF wraps only the AES key, requires user verification and reopens authenticated entries', async t => {
  const env = environment(t)
  const bytes = new Uint8Array(Buffer.from(fixture.data_key_hex, 'hex'))
  await saveDeviceUnlock(1, fixture.vault, bytes, signal())
  assert.equal(hasDeviceUnlock(1, fixture.vault), true)
  const stored = [...env.store.values()].join('')
  assert.ok(!stored.includes(fixture.master))
  assert.ok(!stored.includes(Buffer.from(bytes).toString('base64')))
  const key = await openDeviceUnlock(1, fixture.vault, signal())
  assert.equal(key.extractable, false)
  assert.deepEqual(await decryptEntry(key, fixture.entry), fixture.payload)
  assert.equal(env.calls[0].publicKey.authenticatorSelection.userVerification, 'required')
  assert.equal(env.calls[0].publicKey.authenticatorSelection.authenticatorAttachment, 'platform')
  assert.ok(env.calls.slice(1).every(options => options.publicKey.userVerification === 'required'))
  assert.equal(hasDeviceUnlock(2, fixture.vault), false)
  forgetDeviceUnlock(1, fixture.vault)
  assert.equal(hasDeviceUnlock(1, fixture.vault), false)
})

test('wrong PRF, tampered ciphertext and changed master wrappers fail closed', async t => {
  const env = environment(t)
  await saveDeviceUnlock(1, fixture.vault, new Uint8Array(Buffer.from(fixture.data_key_hex, 'hex')), signal())
  env.changeSecret()
  await assert.rejects(openDeviceUnlock(1, fixture.vault, signal()))
  const calls = env.calls.length
  await assert.rejects(openDeviceUnlock(1, { ...fixture.vault, wrap_nonce: Buffer.alloc(12, 3).toString('base64') }, signal()), /changed/)
  assert.equal(env.calls.length, calls)
  const [name, raw] = [...env.store.entries()][0]
  const record = JSON.parse(raw)
  record.wrapped = Buffer.alloc(48, 5).toString('base64')
  env.store.set(name, JSON.stringify(record))
  await assert.rejects(openDeviceUnlock(1, fixture.vault, signal()))
})

test('unsupported authenticators and canceled ceremonies save no encrypted key', async t => {
  const env = environment(t)
  env.credentials.create = async () => ({ getClientExtensionResults: () => ({}) })
  const bytes = new Uint8Array(32)
  await assert.rejects(saveDeviceUnlock(1, fixture.vault, bytes, signal()), /not supported/)
  assert.equal(env.store.size, 0)
  const abort = new AbortController()
  env.credentials.create = async () => { abort.abort(); return { getClientExtensionResults: () => ({ prf: { enabled: true } }) } }
  await assert.rejects(saveDeviceUnlock(1, fixture.vault, bytes, abort.signal))
  assert.equal(env.store.size, 0)
})

function property(t, object, name, descriptor) {
  const previous = Object.getOwnPropertyDescriptor(object, name)
  Object.defineProperty(object, name, descriptor)
  t.after(() => { if (previous) Object.defineProperty(object, name, previous); else delete object[name] })
}
