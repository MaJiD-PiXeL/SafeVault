import assert from 'node:assert/strict'
import { test } from 'node:test'
import { ApiError, createAccountApi } from '../src/api.ts'

const token = 'a'.repeat(64)
const rotated = 'b'.repeat(64)
const user = { id: 1, username: 'test-user' }
const sessionId = 'fa80ff00-d5bc-4000-8ad5-d76a91ef5993'

test('bootstraps CSRF, sends only account credentials and uses rotated tokens', async (t) => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push([url, options])
    if (url.endsWith('/session/')) return Response.json({ user: null, csrfToken: token })
    if (url.endsWith('/login/')) return Response.json({ user, csrfToken: rotated })
    return Response.json({ user: null, csrfToken: token })
  })
  const api = createAccountApi('/api')
  assert.deepEqual((await api.signIn('test-user', '  account only  ')).user, user)
  assert.equal(calls[0][0], '/api/auth/session/')
  assert.equal(calls[1][1].headers['X-CSRFToken'], token)
  assert.deepEqual(JSON.parse(calls[1][1].body), { username: 'test-user', password: '  account only  ' })
  await api.signOut()
  assert.equal(calls[2][1].headers['X-CSRFToken'], rotated)
  for (const [, options] of calls) {
    assert.equal(options.credentials, 'include')
    assert.equal(options.cache, 'no-store')
    assert.equal(options.redirect, 'error')
    assert.ok(options.signal instanceof AbortSignal)
  }
})

test('registration uses the configured API origin and an explicit credential payload', async (t) => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push([url, options])
    return Response.json({ user: options.method === 'GET' ? null : user, csrfToken: token })
  })
  await createAccountApi('https://api.example/api/').register('test-user', 'account password')
  assert.equal(calls[1][0], 'https://api.example/api/auth/register/')
  assert.equal(calls[1][1].method, 'POST')
  assert.equal(calls[1][1].headers['Content-Type'], 'application/json')
  assert.deepEqual(Object.keys(JSON.parse(calls[1][1].body)), ['username', 'password'])
})

test('a late session check cannot overwrite the token rotated by sign-in', async (t) => {
  let sessionRequests = 0
  let releaseSession
  const late = new Promise((resolve) => { releaseSession = resolve })
  let logoutToken
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    if (url.endsWith('/session/')) {
      sessionRequests += 1
      return sessionRequests === 1 ? Response.json({ user: null, csrfToken: token }) : late
    }
    if (url.endsWith('/logout/')) logoutToken = options.headers['X-CSRFToken']
    return Response.json({ user, csrfToken: rotated })
  })
  const api = createAccountApi()
  await api.session()
  const pending = api.session()
  await api.signIn('test-user', 'account password')
  releaseSession(Response.json({ user: null, csrfToken: token }))
  await pending
  await api.signOut()
  assert.equal(logoutToken, rotated)
})

test('a CSRF failure is not replayed; the next explicit attempt fetches a new token', async (t) => {
  const calls = []
  t.mock.method(globalThis, 'fetch', async (url) => {
    calls.push(url)
    if (url.endsWith('/session/')) return Response.json({ user: null, csrfToken: token })
    return Response.json({ detail: 'Refresh and try again.', code: 'csrf_failed' }, { status: 403 })
  })
  const api = createAccountApi()
  await assert.rejects(api.signIn('user', 'password'), { message: 'Refresh and try again.', status: 403 })
  assert.equal(calls.length, 2)
  await assert.rejects(api.signIn('user', 'password'), ApiError)
  assert.equal(calls.length, 4)
  assert.equal(calls[2], '/api/auth/session/')
})

test('reports password validation and lockout errors without substituting success', async (t) => {
  for (const [body, status, message] of [
    [{ password: ['Use a longer account password.'] }, 400, 'Use a longer account password.'],
    [{ detail: 'Try again later.' }, 429, 'Try again later.'],
  ]) {
    const mock = t.mock.method(globalThis, 'fetch', async (url) => url.endsWith('/session/')
      ? Response.json({ user: null, csrfToken: token }) : Response.json(body, { status }))
    await assert.rejects(createAccountApi().register('user', 'password'), { message, status })
    mock.mock.restore()
  }
})

test('rejects malformed account responses and non-JSON errors', async (t) => {
  for (const body of [{ user, csrfToken: 'invalid' }, { user: { id: '1', username: 'user' }, csrfToken: token }, {}]) {
    const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(body))
    await assert.rejects(createAccountApi().session(), /Unexpected account response/)
    mock.mock.restore()
  }
  t.mock.method(globalThis, 'fetch', async () => new Response('<html>error</html>', { status: 500 }))
  await assert.rejects(createAccountApi().session(), /Unexpected server response/)
})

test('lists and revokes sessions without returning bearer cookie values', async (t) => {
  const record = { id: sessionId, createdAt: '2026-10-31T12:00:00Z', expiresAt: '2026-10-31T12:30:00Z', current: false }
  const calls = []
  t.mock.method(globalThis, 'fetch', async (url, options) => {
    calls.push([url, options])
    if (options.method === 'DELETE') return new Response(null, { status: 204 })
    return url.endsWith('/sessions/') ? Response.json({ sessions: [record] }) : Response.json({ user, csrfToken: token })
  })
  const api = createAccountApi()
  assert.deepEqual(await api.sessions(), [record])
  await api.revokeSession(sessionId)
  assert.equal(calls.at(-1)[0], `/api/auth/sessions/${sessionId}/`)
  assert.equal(calls.at(-1)[1].method, 'DELETE')
  await assert.rejects(api.revokeSession('../logout'), /Invalid session identifier/)
})

test('rejects invalid session list data and propagates cancellation', async (t) => {
  const mock = t.mock.method(globalThis, 'fetch', async () => Response.json({ sessions: [{ id: 'invalid' }] }))
  await assert.rejects(createAccountApi().sessions(), /Unexpected sessions response/)
  mock.mock.restore()
  t.mock.method(globalThis, 'fetch', async (_, options) => { options.signal.throwIfAborted() })
  const controller = new AbortController()
  controller.abort()
  await assert.rejects(createAccountApi().session(controller.signal), { name: 'AbortError' })
})
