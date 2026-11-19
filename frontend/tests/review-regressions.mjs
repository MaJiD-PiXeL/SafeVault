// Browser regressions use only public fixtures and intercepted, synthetic APIs.
import assert from 'node:assert/strict'
import { createServer as createHttpServer } from 'node:http'
import { readFile, mkdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createServer as createViteServer } from 'vite'
import ts from 'typescript'

const require = createRequire(import.meta.url)
const { chromium } = require(process.env.SAFEVAULT_PLAYWRIGHT ?? 'playwright')
const frontend = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(frontend, 'dist')
const output = resolve(frontend, '../native/extension/dist/verification')
const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml', '.ttf': 'font/ttf', '.png': 'image/png' }
const site = createHttpServer(async (request, response) => {
  try {
    const pathname = new URL(request.url, 'http://127.0.0.1').pathname
    const file = resolve(dist, '.' + (pathname === '/' ? '/index.html' : pathname))
    if (!file.startsWith(dist + sep)) throw new Error('Invalid path')
    response.setHeader('Content-Type', types[extname(file)] ?? 'application/octet-stream')
    response.end(await readFile(file))
  } catch { response.writeHead(404); response.end() }
})
await new Promise(done => site.listen(0, '127.0.0.1', done))
const origin = `http://127.0.0.1:${site.address().port}`

const fixtureModule = `
import React, { useState } from 'react';
import { createRoot } from 'react-dom/client';
import DeviceUnlockPanel from '/src/vault/DeviceUnlockPanel.tsx';
import fixture from '/tests/fixtures/encryption-v1.json';
const second = { ...fixture.vault, id: '225830f6-22d3-4f14-a3f0-b211f7db698d' };
let state = { unlocked: true, vaults: [fixture.vault, second], selectedId: fixture.vault.id, ownerId: 1, lockEpoch: 0, busy: false };
const controller = { getSnapshot: () => state };
function Fixture() {
  const [, render] = useState(0);
  window.reviewRender = patch => { state = { ...state, ...patch }; render(value => value + 1); };
  return React.createElement(DeviceUnlockPanel, { controller });
}
createRoot(document.getElementById('root')).render(React.createElement(Fixture));
`
const vite = await createViteServer({ root: frontend, configFile: false, logLevel: 'error',
  server: { host: '127.0.0.1', port: 0 }, plugins: [{
    name: 'isolated-review-fixture', enforce: 'pre',
    configureServer(server) {
      server.middlewares.use((request, response, next) => {
        if (request.url !== '/review-fixture.html') return next()
        response.setHeader('Content-Type', 'text/html')
        response.end('<!doctype html><div id="root"></div><script type="module" src="/review-fixture.js"></script>')
      })
    },
    resolveId(id) { if (id === '/review-fixture.js') return '\0review-fixture' },
    load(id) { if (id === '\0review-fixture') return fixtureModule },
    transform(code, id) {
      if (id.endsWith('.tsx')) return ts.transpileModule(code, { compilerOptions: {
        jsx: ts.JsxEmit.ReactJSX, target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext,
      } }).outputText
    },
  }] })
let browser
try {
  await vite.listen()
  browser = await chromium.launch({ headless: true,
    ...(process.env.SAFEVAULT_BROWSER ? { executablePath: process.env.SAFEVAULT_BROWSER } : {}) })
  const context = await browser.newContext({ serviceWorkers: 'block' })
  const device = await context.newPage()
  await device.goto(`http://127.0.0.1:${vite.httpServer.address().port}/review-fixture.html`)
  const master = device.getByLabel('Current master password', { exact: true })
  await master.fill('PUBLIC transient master phrase')
  await device.evaluate(() => window.reviewRender({ unlocked: false, lockEpoch: 1 }))
  await master.waitFor({ state: 'hidden' })
  await device.evaluate(() => window.reviewRender({ unlocked: true }))
  await master.waitFor()
  assert.equal(await master.inputValue(), '')
  await master.fill('PUBLIC different vault phrase')
  await device.evaluate(() => window.reviewRender({ selectedId: '225830f6-22d3-4f14-a3f0-b211f7db698d' }))
  assert.equal(await master.inputValue(), '')

  let enabled = false
  let address = { email: 'old@example.test', verified: true }
  const emailActions = []
  const actions = []
  const codes = Array.from({ length: 10 }, (_, index) => `${String(index).padStart(8, '0')}-12345678-12345678-12345678`)
  await context.route('**/api/**', async route => {
    const request = route.request()
    const path = new URL(request.url()).pathname
    let data
    if (path.endsWith('/auth/session/')) data = { user: { id: 1, username: 'review-user' }, csrfToken: 'a'.repeat(64) }
    else if (path.endsWith('/auth/sessions/')) data = { sessions: [] }
    else if (path.endsWith('/auth/mfa/')) {
      if (request.method() === 'GET') data = { enabled, recoveryCodesRemaining: enabled ? 10 : 0 }
      else {
        const body = request.postDataJSON(); actions.push(body.action)
        if (body.action === 'begin') data = { secret: 'A'.repeat(32), uri: 'otpauth://totp/public' }
        else if (body.action === 'confirm') { enabled = true; await route.abort('failed'); return }
        else if (body.action === 'regenerate') data = { recoveryCodes: codes }
        else throw new Error('Unexpected verification action')
      }
    } else if (path.endsWith('/recovery/email/')) {
      if (request.method() === 'GET') data = address
      else {
        const body = request.postDataJSON()
        assert.equal(body.password, 'PUBLIC synthetic password')
        assert.equal(body.code, '555555')
        emailActions.push(request.method())
        address = request.method() === 'DELETE' ? { email: null, verified: false } : { email: body.email, verified: false }
        await route.fulfill({ status: 204 }); return
      }
    }
    else if (path.endsWith('/vaults/')) data = { vaults: [] }
    else if (path.endsWith('/security-settings/')) data = { auto_lock_seconds: 300, lock_on_hidden: true }
    else data = { status: 'healthy' }
    await route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) })
  })
  const page = await context.newPage()
  await page.goto(origin)
  await page.getByRole('button', { name: 'review-user', exact: true }).click()
  const factor = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Two-step verification', exact: true }) }).last()
  await factor.getByLabel('Current account password', { exact: true }).fill('PUBLIC synthetic password')
  await factor.getByRole('button', { name: 'Set up authenticator' }).click()
  await factor.locator('code').waitFor()
  await factor.getByLabel('Current account password', { exact: true }).fill('PUBLIC synthetic password')
  await factor.getByLabel('Authenticator code', { exact: true }).fill('123456')
  await factor.getByRole('button', { name: 'Confirm and show recovery codes' }).click()
  await factor.getByText('Enabled · 10 recovery codes remaining.', { exact: true }).waitFor()
  assert.equal(await factor.getByRole('button', { name: 'Confirm and show recovery codes' }).count(), 0)
  await factor.getByRole('status').filter({ hasText: 'did not receive recovery codes' }).waitFor()
  await factor.getByLabel('Current account password', { exact: true }).fill('PUBLIC synthetic password')
  await factor.getByLabel('Authenticator or recovery code', { exact: true }).fill('654321')
  await factor.getByRole('button', { name: 'Generate new recovery codes' }).click()
  await factor.locator('pre').waitFor()
  assert.equal((await factor.locator('pre').innerText()).split('\n').length, 10)
  assert.deepEqual(actions, ['begin', 'confirm', 'regenerate'])

  const recovery = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Recovery email', exact: true }) }).last()
  await recovery.getByLabel('New recovery email', { exact: true }).fill('new@example.test')
  await recovery.getByLabel('Current account password', { exact: true }).fill('PUBLIC synthetic password')
  await recovery.getByLabel('Authenticator or recovery code (if enabled)', { exact: true }).fill('555555')
  await recovery.getByRole('button', { name: 'Change recovery email' }).click()
  await recovery.getByText('new@example.test · Awaiting verification', { exact: true }).waitFor()
  await recovery.getByLabel('Current account password', { exact: true }).fill('PUBLIC synthetic password')
  await recovery.getByLabel('Authenticator or recovery code (if enabled)', { exact: true }).fill('555555')
  await recovery.getByRole('checkbox').check()
  await recovery.getByRole('button', { name: 'Remove recovery email' }).click()
  await recovery.getByRole('status').filter({ hasText: 'Recovery email removed' }).waitFor()
  assert.deepEqual(emailActions, ['POST', 'DELETE'])
  assert.equal(await recovery.getByLabel('Current account password', { exact: true }).inputValue(), '')

  const guest = await browser.newContext({ serviceWorkers: 'block' })
  await guest.route('**/api/**', route => route.fulfill({ contentType: 'application/json', body: JSON.stringify(
    route.request().url().includes('/auth/session/') ? { user: null, csrfToken: 'a'.repeat(64) } : { status: 'healthy' },
  ) }))
  const mobile = await guest.newPage()
  await mobile.goto(origin)
  await mobile.evaluate(() => document.fonts.ready)
  const sizes = []
  await mkdir(output, { recursive: true })
  for (const width of [320, 360, 390]) {
    await mobile.setViewportSize({ width, height: 844 })
    const box = await mobile.getByRole('textbox', { name: 'Search items', exact: true }).boundingBox()
    assert.ok(box.width >= 160, `Search input too small at ${width}: ${box.width}`)
    assert.equal(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true)
    sizes.push({ viewport: width, input: Math.round(box.width) })
    await mobile.screenshot({ path: resolve(output, `review-mobile-${width}.png`), fullPage: true })
  }
  console.log('PASS: transient master state clears on lock/vault switch; lost TOTP response reconciles and regenerates codes; recovery email changes/removal; mobile search', sizes)
} finally {
  await browser?.close()
  await vite.close()
  await new Promise(done => site.close(done))
}
