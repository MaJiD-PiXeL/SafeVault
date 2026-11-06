import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { runInNewContext } from 'node:vm'

test('offline reload serves only the precached public shell and leaves private routes alone', async () => {
  const worker = await readFile(new URL('../scripts/offline-shell.js', import.meta.url), 'utf8')
  const origin = 'https://vault.example.test'
  const assets = ['/index.html', '/assets/main.js', '/assets/argon2.worker.js']
  const listeners = new Map()
  const stored = new Map()
  const cache = {
    async addAll(requests) {
      for (const request of requests) {
        assert.equal(request.credentials, 'omit')
        assert.equal(request.redirect, 'error')
        stored.set(request.url, new Response(new URL(request.url).pathname))
      }
    },
    async match(url) { return stored.get(url)?.clone() },
  }
  let network = true
  runInNewContext(worker, {
    CACHE: 'safevault-offline-shell-current', PREFIX: 'safevault-offline-shell-', ASSETS: assets,
    self: {
      location: { origin },
      addEventListener: (event, handler) => listeners.set(event, handler),
      clients: { async claim() {} },
    },
    caches: { async open() { return cache }, async keys() { return [] } },
    URL, Request, Response,
    async fetch() {
      if (!network) throw new TypeError('Offline')
      return new Response('Network page')
    },
  })
  let install
  listeners.get('install')({ waitUntil(pending) { install = pending } })
  await install
  assert.deepEqual([...stored.keys()], assets.map((path) => origin + path))

  function dispatch(path, { method = 'GET', mode = 'same-origin' } = {}) {
    let result
    const request = { url: new URL(path, origin).href, method, mode }
    listeners.get('fetch')({ request, respondWith(pending) { result = pending } })
    return result
  }

  assert.equal(await (await dispatch('/', { mode: 'navigate' })).text(), 'Network page')
  network = false
  assert.equal(await (await dispatch('/', { mode: 'navigate' })).text(), '/index.html')
  assert.equal(await (await dispatch('/assets/argon2.worker.js')).text(), '/assets/argon2.worker.js')
  assert.equal(dispatch('/api/vaults/', { mode: 'navigate' }), undefined)
  assert.equal(dispatch('/api/auth/recovery/reset/', { method: 'POST' }), undefined)
  assert.equal(dispatch('/assets/main.js?other=1'), undefined)
  assert.equal(dispatch('https://unrelated.example/assets/main.js'), undefined)
})
