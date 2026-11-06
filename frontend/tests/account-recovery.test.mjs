import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readAccountLink } from '../src/accountLink.ts'
import { createAccountApi } from '../src/api.ts'

const username = 'recovery-owner'
const token = 'abc123-' + 'b'.repeat(32)

test('account email fragments accept the expected fields and reject ambiguous links', () => {
  const reset = `#account-action=reset&username=${username}&token=${token}`
  assert.deepEqual(readAccountLink(reset), { valid: true, link: { action: 'reset', username, token } })
  assert.equal(readAccountLink('#overview'), null)
  for (const bad of [reset + '&username=other', reset.replace('reset', 'unknown'), reset.replace(token, 'short')]) {
    assert.deepEqual(readAccountLink(bad), { valid: false })
  }
})

test('recovery credentials and tokens travel only in CSRF-protected JSON bodies', async (t) => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push({ url, options })
    if (url.endsWith('/session/')) return Response.json({ user: null, csrfToken: 'a'.repeat(64) })
    if (options.method === 'GET') return Response.json({ email: 'owner@example.test', verified: true })
    if (url.endsWith('/request/')) return Response.json({ accepted: true }, { status: 202 })
    return new Response(null, { status: 204 })
  })
  const account = createAccountApi('/api')
  const password = '  PUBLIC account password  '
  assert.deepEqual(await account.recoveryEmail(), { email: 'owner@example.test', verified: true })
  await account.enrollRecoveryEmail('owner@example.test', password)
  await account.verifyRecoveryEmail(username, token)
  await account.requestPasswordReset(username)
  await account.resetAccountPassword(username, token, password)
  const writes = calls.filter(({ options }) => options.method === 'POST')
  assert.deepEqual(writes.map(({ url }) => url), [
    '/api/auth/recovery/email/', '/api/auth/recovery/verify/', '/api/auth/recovery/request/', '/api/auth/recovery/reset/',
  ])
  assert.deepEqual(writes.map(({ options }) => JSON.parse(options.body)), [
    { email: 'owner@example.test', password }, { username, token }, { username }, { username, token, password },
  ])
  assert.ok(writes.every(({ options }) => options.headers['X-CSRFToken'] === 'a'.repeat(64)))
})
