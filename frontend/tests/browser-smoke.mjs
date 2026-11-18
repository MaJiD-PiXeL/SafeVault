// Run against deploy/local-beta.py on its own unused port, never a real vault.
import assert from 'node:assert/strict'
import { createHmac, randomUUID } from 'node:crypto'
import { mkdir } from 'node:fs/promises'
import { createRequire } from 'node:module'
import { resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { fillLogin } from '../../native/extension/fill.js'

const require = createRequire(import.meta.url)
const { chromium } = require(process.env.SAFEVAULT_PLAYWRIGHT ?? 'playwright')
const origin = process.env.SAFEVAULT_SMOKE_ORIGIN ?? 'http://127.0.0.1:18031'
assert.match(origin, /^http:\/\/127\.0\.0\.1:18[0-9]{3}$/)
const browser = await chromium.launch({ headless: true,
  ...(process.env.SAFEVAULT_BROWSER ? { executablePath: process.env.SAFEVAULT_BROWSER } : {}) })
const context = await browser.newContext({ viewport: { width: 1280, height: 900 } })
const page = await context.newPage()
page.setDefaultTimeout(15000)
const errors = []
page.on('pageerror', error => errors.push(error.message))
const username = `smoke-${randomUUID().slice(0, 12)}`
const password = 'PUBLIC synthetic account phrase 639!'
const master = 'PUBLIC synthetic master phrase 728!'
const targetOrigin = 'https://fill.example.test'

function totp(secret) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
  let bits = ''
  for (const letter of secret) bits += alphabet.indexOf(letter).toString(2).padStart(5, '0')
  const key = Buffer.from(bits.match(/.{8}/g).map(byte => Number.parseInt(byte, 2)))
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)))
  const digest = createHmac('sha1', key).update(counter).digest()
  const value = digest.readUInt32BE(digest.at(-1) & 15) & 0x7fffffff
  return String(value % 1000000).padStart(6, '0')
}

try {
  await page.goto(origin)
  await page.getByRole('button', { name: 'Sign in', exact: true }).first().click()
  await page.getByRole('button', { name: 'Create account', exact: true }).first().click()
  await page.getByRole('textbox', { name: /^Username/ }).fill(username)
  await page.getByLabel('Account password', { exact: true }).fill(password)
  await page.getByLabel('Confirm account password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Create account', exact: true }).last().click()
  await page.getByRole('heading', { name: 'Active browser sessions' }).waitFor()

  await page.getByRole('button', { name: /^All Passwords/ }).first().click()
  await page.getByRole('heading', { name: 'Create your encrypted vault' }).waitFor()
  await page.getByLabel('Master password', { exact: true }).fill(master)
  await page.getByLabel('Confirm master password', { exact: true }).fill(master)
  await page.getByRole('button', { name: 'Create encrypted vault', exact: true }).click()
  await page.getByRole('button', { name: 'Lock vault', exact: true }).first().waitFor()
  await page.getByRole('button', { name: 'Add New Item', exact: true }).click()
  const dialog = page.getByRole('dialog')
  await dialog.getByLabel('Title', { exact: true }).fill('PUBLIC smoke login')
  await dialog.getByLabel('Username / Email', { exact: true }).fill('public-smoke-user')
  await dialog.getByLabel('Password', { exact: true }).fill('PUBLIC synthetic entry 52!')
  await dialog.getByLabel(/Website/).fill(targetOrigin + '/login')
  await dialog.getByRole('button', { name: 'Save encrypted entry' }).click()
  await dialog.waitFor({ state: 'hidden' })
  await page.getByText('PUBLIC smoke login', { exact: true }).waitFor()
  const local = await page.evaluate(() => JSON.stringify({ ...localStorage }))
  assert.ok(!local.includes(master) && !local.includes('PUBLIC smoke login') && !local.includes('PUBLIC synthetic entry 52!'))
  await page.reload()
  await page.getByRole('heading', { name: 'Your vault is locked' }).waitFor()
  await page.getByLabel('Master password', { exact: true }).fill(master)
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click()
  await page.getByText('PUBLIC smoke login', { exact: true }).waitFor()

  await page.getByRole('button', { name: username, exact: true }).click()
  const factor = page.locator('section').filter({ has: page.getByRole('heading', { name: 'Two-step verification', exact: true }) }).last()
  await factor.getByLabel('Current account password', { exact: true }).fill(password)
  await factor.getByRole('button', { name: 'Set up authenticator' }).click()
  await factor.locator('code').waitFor()
  const secret = await factor.locator('code').innerText()
  await factor.getByLabel('Current account password', { exact: true }).fill(password)
  await factor.getByLabel('Authenticator code', { exact: true }).fill(totp(secret))
  await factor.getByRole('button', { name: 'Confirm and show recovery codes' }).click()
  await factor.locator('pre').waitFor()
  const codes = (await factor.locator('pre').innerText()).split('\n')
  assert.equal(codes.length, 10)
  await page.getByRole('button', { name: 'Sign out', exact: true }).click()
  await page.getByRole('textbox', { name: /^Username/ }).fill(username)
  await page.getByLabel('Account password', { exact: true }).fill(password)
  await page.getByRole('button', { name: 'Sign in', exact: true }).last().click()
  await page.getByRole('alert').filter({ hasText: 'Enter a fresh authenticator code' }).waitFor()
  await page.getByLabel('Account password', { exact: true }).fill(password)
  await page.getByLabel('Authenticator or recovery code (if enabled)', { exact: true }).fill(codes[0])
  await page.getByRole('button', { name: 'Sign in', exact: true }).last().click()
  await page.getByRole('heading', { name: 'Active browser sessions' }).waitFor()
  await factor.getByText('Enabled · 9 recovery codes remaining.', { exact: true }).waitFor()
  await page.getByRole('button', { name: /^All Passwords/ }).first().click()
  await page.getByLabel('Master password', { exact: true }).fill(master)
  await page.getByRole('button', { name: 'Unlock vault', exact: true }).click()
  await page.getByText('PUBLIC smoke login', { exact: true }).waitFor()
  const output = fileURLToPath(new URL('../../native/extension/dist/verification/', import.meta.url))
  await mkdir(output, { recursive: true })
  await page.screenshot({ path: resolve(output, 'desktop.png'), fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth), true)
  await page.screenshot({ path: resolve(output, 'mobile.png'), fullPage: true })

  // A local synthetic HTTPS fixture exercises the actual isolated fill function.
  await context.route(targetOrigin + '/**', route => route.fulfill({ contentType: 'text/html', body:
    '<form onsubmit="window.submitted=true;return false"><label>Username<input name="username" autocomplete="username"></label><label>Password<input name="password" type="password"></label><button>Sign in</button></form>' }))
  const target = await context.newPage()
  await target.goto(targetOrigin + '/login')
  await target.addScriptTag({ content: 'window.testFill = ' + fillLogin.toString() })
  assert.equal(await target.evaluate(origin => window.testFill(origin, 'public-smoke-user', 'PUBLIC fill value'), targetOrigin), true)
  assert.equal(await target.getByLabel('Username').inputValue(), 'public-smoke-user')
  assert.equal(await target.getByLabel('Password').inputValue(), 'PUBLIC fill value')
  assert.equal(await target.evaluate(() => Boolean(window.submitted)), false)
  assert.deepEqual(errors, [])
  console.log('PASS: browser registration, real Worker crypto, encrypted save, locked reload, history, TOTP enrollment, recovery login, mobile layout, DOM autofill; no page errors.')
} finally { await browser.close() }
