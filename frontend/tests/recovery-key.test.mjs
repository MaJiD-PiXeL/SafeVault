import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'
import { createVaultApi } from '../src/vault/api.ts'
import { deriveArgon2id } from '../src/vault/argon2.ts'
import { VaultController } from '../src/vault/controller.ts'
import { createRecoveryKey, decryptEntry, rewrapWithRecovery, unlockEncryptedVault } from '../src/vault/crypto.ts'

const fixture = JSON.parse(await readFile(new URL('./fixtures/encryption-v1.json', import.meta.url), 'utf8'))
const next = '  Public synthetic recovered master 🔑  '
const signal = () => new AbortController().signal
const derive = (password, salt) => deriveArgon2id(new TextEncoder().encode(password), salt)
const fastDerive = async (password, salt) => password === fixture.master && Buffer.from(salt).toString('base64') === fixture.vault.kdf_salt
  ? Buffer.from(fixture.wrapping_key_hex, 'hex') : createHash('sha256').update(password).update(salt).digest()

test('recovery keeps the same data key and binds the encrypted wrapper to its vault and key version', async () => {
  const { code, recovery } = await createRecoveryKey(fixture.vault, fixture.master, derive, signal())
  assert.match(code, /^SV1-[A-Za-z0-9_-]{43}$/)
  const vault = { ...fixture.vault, recovery }
  for (const substituted of [{ ...vault, id: crypto.randomUUID() }, { ...vault, key_version: 2 }]) {
    await assert.rejects(rewrapWithRecovery(substituted, code, next, derive, signal()), /could not open/)
  }
  await assert.rejects(rewrapWithRecovery(vault, 'SV1-' + Buffer.alloc(32, 7).toString('base64url'), next, derive, signal()))
  const updated = await rewrapWithRecovery(vault, code, next, derive, signal())
  assert.equal(updated.vault.recovery, undefined)
  assert.deepEqual(await decryptEntry(updated.key, fixture.entry), fixture.payload)
  await assert.rejects(unlockEncryptedVault(updated.vault, fixture.master, derive, signal()))
  assert.deepEqual(await decryptEntry(await unlockEncryptedVault(updated.vault, next, derive, signal()), fixture.entry), fixture.payload)
})

test('canceled drafts do not write, activation sends only an encrypted wrapper, and recovery consumes it', async () => {
  let remote = fixture.vault
  const writes = []
  const api = createVaultApi(async (path, method, body) => {
    if (path === 'vaults') return { vaults: [remote] }
    if (path === 'security-settings') return { auto_lock_seconds: 300, lock_on_hidden: false }
    if (path.includes('entries?')) return { count: 1, next: null, results: [fixture.entry], key_version: 1 }
    writes.push({ method, body })
    if (path.endsWith('recovery-key')) {
      remote = { ...remote, recovery: body.recovery }
      return remote
    }
    if (path.endsWith('recover')) {
      const { kdf_salt, wrap_nonce, wrapped_key } = body
      remote = { ...remote, kdf_salt, wrap_nonce, wrapped_key, recovery: null }
      return remote
    }
    throw new Error('Unexpected request')
  })
  const c = new VaultController(api, fastDerive)
  c.switchAccount(1, false)
  assert.equal(await c.load(), true)
  assert.equal(await c.unlock(fixture.master), true)
  assert.equal(await c.prepareRecovery(fixture.master), true)
  c.hidden()
  assert.equal(c.getSnapshot().unlocked, true)
  assert.equal(c.getSnapshot().recoveryCode, null)
  assert.equal(writes.length, 0)
  assert.equal(await c.prepareRecovery(fixture.master), true)
  const code = c.getSnapshot().recoveryCode
  assert.equal(await c.confirmRecovery(), true)
  assert.equal(c.getSnapshot().recoveryCode, null)
  assert.deepEqual(Object.keys(writes[0].body.recovery).sort(), ['nonce', 'wrapped_key'])
  c.lock()
  assert.equal(await c.recoverWithKey(code, next), true)
  assert.equal(c.getSnapshot().unlocked, false)
  assert.equal(c.getSnapshot().vaults[0].recovery, undefined)
  for (const write of writes) for (const secret of [code, next, fixture.master]) assert.ok(!JSON.stringify(write).includes(secret))
  assert.equal(await c.recoverWithKey(code, fixture.master), false)
  assert.equal(writes.length, 2)
  assert.equal(await c.unlock(next), true)
  assert.deepEqual(c.getSnapshot().entries[0].data, fixture.payload)
})
