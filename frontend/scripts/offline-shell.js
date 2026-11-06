self.addEventListener('install', (event) => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE)
    const requests = ASSETS.map((path) => new Request(new URL(path, self.location.origin), {
      credentials: 'omit', cache: 'reload', redirect: 'error',
    }))
    await cache.addAll(requests)
  })())
})

self.addEventListener('activate', (event) => {
  event.waitUntil((async () => {
    for (const key of await caches.keys()) {
      if (key.startsWith(PREFIX) && key !== CACHE) await caches.delete(key)
    }
    await self.clients.claim()
  })())
})

self.addEventListener('fetch', (event) => {
  const request = event.request
  const url = new URL(request.url)
  if (request.method !== 'GET' || url.origin !== self.location.origin) return

  if (request.mode === 'navigate' && (url.pathname === '/' || url.pathname === '/index.html')) {
    event.respondWith(fetch(request).catch(async () => {
      const cache = await caches.open(CACHE)
      const index = new URL('/index.html', self.location.origin).href
      return (await cache.match(index, { ignoreVary: true })) || Response.error()
    }))
    return
  }

  if (url.search || !ASSETS.includes(url.pathname)) return
  event.respondWith((async () => {
    const cache = await caches.open(CACHE)
    return (await cache.match(url.href, { ignoreVary: true })) || fetch(request)
  })())
})
