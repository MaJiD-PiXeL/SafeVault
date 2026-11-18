import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFillRequest, matchesFill, pairExtension, sendFill } from '../src/vault/autofill.ts'
import { authorized } from '../../native/extension/policy.js'
import { fillLogin } from '../../native/extension/fill.js'

const extension = 'a'.repeat(32)
const token = '225830f6-22d3-4f14-a3f0-b211f7db698d'
const origin = 'https://example.com'
const data = { schema_version: 1, website: origin + '/login', username: 'public-user', password: 'synthetic-secret' }

test('autofill accepts strict one-use routing and matches exact HTTPS origins', () => {
  const valid = '#' + new URLSearchParams({ autofill: extension, token, origin })
  assert.equal(readFillRequest(valid).origin, origin)
  for (const hash of [valid + '&origin=' + origin, valid + '&other=x', valid.replace(token, 'bad'), valid.replace('autofill=aaa', 'autofill=zzz')]) {
    assert.equal(readFillRequest(hash), null)
  }
  assert.equal(matchesFill(data, origin), true)
  for (const website of ['http://example.com', 'https://evil.example.com', 'https://example.com.evil.test', 'https://u:p@example.com']) {
    assert.equal(matchesFill({ ...data, website }, origin), false)
  }
})

test('extension refuses other senders, frames, origins, expired tokens and malformed credentials', () => {
  const now = Date.now()
  const pending = { sourceTab: 9, token, origin, expires: now + 60000 }
  const sender = { frameId: 0, url: 'https://vault.test/', tab: { id: 9 } }
  const message = { type: 'safevault.fill.v1', token, origin, username: data.username, password: data.password }
  assert.equal(authorized(message, sender, pending, 'https://vault.test', now), true)
  for (const changed of [{ frameId: 1 }, { url: 'https://evil.test/' }, { tab: { id: 10 } }, { url: 'https://vault.test.evil.test/' }]) {
    assert.equal(authorized(message, { ...sender, ...changed }, pending, 'https://vault.test', now), false)
  }
  for (const changed of [{ token: 'other' }, { origin: 'https://evil.test' }, { password: {} }]) {
    assert.equal(authorized({ ...message, ...changed }, sender, pending, 'https://vault.test', now), false)
  }
  assert.equal(authorized(message, sender, pending, 'https://vault.test', now + 60000), false)
})

test('web vault sends only explicitly paired matching credentials and never persists plaintext', async t => {
  const store = new Map()
  property(t, globalThis, 'localStorage', { value: { getItem: key => store.get(key) ?? null, setItem: (key, value) => store.set(key, value), removeItem: key => store.delete(key) }, configurable: true })
  const calls = []
  property(t, globalThis, 'chrome', { value: { runtime: { sendMessage: async (...args) => { calls.push(args); return { ok: true } } } }, configurable: true })
  const request = { extension, token, origin, created: Date.now() }
  await assert.rejects(sendFill(1, request, data), /not paired/)
  pairExtension(1, extension)
  await assert.rejects(sendFill(1, { ...request, origin: 'https://evil.test' }, data))
  await assert.rejects(sendFill(1, { ...request, created: Date.now() - 120000 }, data))
  assert.equal(calls.length, 0)
  await sendFill(1, request, data)
  assert.equal(calls.length, 1)
  assert.equal(calls[0][1].password, data.password)
  assert.ok(![...store.values()].join('').includes(data.password))
})

test('injected fill stops on a changed origin, cross-origin form or ambiguous password fields', t => {
  const window = {}; window.top = window
  property(t, globalThis, 'window', { value: window, configurable: true })
  property(t, globalThis, 'location', { value: { origin, protocol: 'https:', href: origin + '/login' }, configurable: true })
  property(t, globalThis, 'getComputedStyle', { value: () => ({ visibility: 'visible', display: 'block' }), configurable: true })
  const input = { getClientRects: () => [1], form: { action: 'https://evil.test/' } }
  property(t, globalThis, 'document', { value: { querySelectorAll: () => [input] }, configurable: true })
  assert.equal(fillLogin('https://evil.test', 'u', 'p'), false)
  assert.equal(fillLogin(origin, 'u', 'p'), false)
  document.querySelectorAll = () => [input, input]
  assert.equal(fillLogin(origin, 'u', 'p'), false)
})

function property(t, object, name, descriptor) {
  const previous = Object.getOwnPropertyDescriptor(object, name)
  Object.defineProperty(object, name, descriptor)
  t.after(() => { if (previous) Object.defineProperty(object, name, previous); else delete object[name] })
}
