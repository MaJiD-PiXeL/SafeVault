import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkHealth } from '../src/api.ts'

test('uses the same-origin API and accepts a healthy response', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch', async () => Response.json({ status: 'healthy' }))
  assert.equal(await checkHealth(new AbortController().signal), 'healthy')
  assert.equal(fetchMock.mock.calls[0].arguments[0], '/api/health/')
  assert.ok(fetchMock.mock.calls[0].arguments[1].signal instanceof AbortSignal)
})

test('supports an explicitly configured API URL without a double slash', async (t) => {
  const fetchMock = t.mock.method(globalThis, 'fetch', async () => Response.json({ status: 'healthy' }))
  await checkHealth(new AbortController().signal, 'https://api.example/api/')
  assert.equal(fetchMock.mock.calls[0].arguments[0], 'https://api.example/api/health/')
})

test('rejects HTTP errors', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('', { status: 503 }))
  await assert.rejects(checkHealth(new AbortController().signal), /API request failed/)
})

test('rejects invalid health payloads instead of displaying a connected status', async (t) => {
  for (const payload of [null, {}, [], { status: 'unhealthy' }, { status: 123 }]) {
    const mock = t.mock.method(globalThis, 'fetch', async () => Response.json(payload))
    await assert.rejects(checkHealth(new AbortController().signal), /Unexpected API health response/)
    mock.mock.restore()
  }
})

test('rejects invalid JSON', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => new Response('<html>not JSON</html>'))
  await assert.rejects(checkHealth(new AbortController().signal), SyntaxError)
})

test('passes request cancellation to fetch', async (t) => {
  const controller = new AbortController()
  controller.abort()
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    options.signal.throwIfAborted()
  })
  await assert.rejects(checkHealth(controller.signal), { name: 'AbortError' })
})

test('propagates network failures', async (t) => {
  t.mock.method(globalThis, 'fetch', async () => { throw new TypeError('network unavailable') })
  await assert.rejects(checkHealth(new AbortController().signal), /network unavailable/)
})

test('bounds requests with a five-second timeout', async (t) => {
  const timeout = t.mock.method(AbortSignal, 'timeout', () => AbortSignal.abort(new DOMException('Timed out', 'TimeoutError')))
  t.mock.method(globalThis, 'fetch', async (_url, options) => {
    options.signal.throwIfAborted()
  })
  await assert.rejects(checkHealth(new AbortController().signal), { name: 'TimeoutError' })
  assert.equal(timeout.mock.calls[0].arguments[0], 5000)
})
