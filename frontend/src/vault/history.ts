import { fromBase64, object, UUID, VaultDataError } from './format.ts'
import type { EncryptedEntry, VaultMetadata } from './format.ts'

type Mark = { revision: number; state: number; keyVersion: number; digest: string; removed: boolean }
type History = { version: 1; keyVersion: number; wrappers: string[]; entries: Record<string, Mark> }
export type HistoryGuard = { observe: (owner: number, vault: VaultMetadata, entries: EncryptedEntry[], signal: AbortSignal, removed?: string[]) => Promise<void> }
const prefix = 'safevault.history.v1:'
const digestPattern = /^[0-9a-f]{64}$/
const rollback = () => new VaultDataError('This vault returned older or inconsistent data previously seen by this browser. Access was stopped. Check the server or your backup before resetting browser history in Security Center.')

async function digest(bytes: Uint8Array<ArrayBuffer>) {
  return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), byte => byte.toString(16).padStart(2, '0')).join('')
}

function read(raw: string | null): History | null {
  if (raw === null) return null
  try {
    if (raw.length > 4 * 1024 * 1024) throw new Error()
    const value: unknown = JSON.parse(raw)
    if (!object(value) || value.version !== 1 || !Number.isSafeInteger(value.keyVersion) || (value.keyVersion as number) < 1 ||
        !Array.isArray(value.wrappers) || !value.wrappers.length || value.wrappers.length > 1000 ||
        !value.wrappers.every(item => typeof item === 'string' && digestPattern.test(item)) || !object(value.entries) ||
        Object.keys(value.entries).length > 20000) throw new Error()
    for (const [id, mark] of Object.entries(value.entries)) {
      if (!UUID.test(id) || !object(mark) || !Number.isSafeInteger(mark.revision) || (mark.revision as number) < 1 ||
          !Number.isSafeInteger(mark.state) || (mark.state as number) < 1 || typeof mark.digest !== 'string' ||
          !Number.isSafeInteger(mark.keyVersion) || (mark.keyVersion as number) < 1 ||
          !digestPattern.test(mark.digest) || typeof mark.removed !== 'boolean') throw new Error()
    }
    return value as History
  } catch { throw new VaultDataError('Browser vault history is damaged. Check your backup before explicitly resetting it in Security Center.') }
}

function key(owner: number, vault: string) {
  if (!Number.isSafeInteger(owner) || owner < 1 || !UUID.test(vault)) throw new VaultDataError()
  return `${prefix}${owner}:${vault}`
}

export function resetBrowserHistory(owner: number, vault: string) { localStorage.removeItem(key(owner, vault)) }

export function createHistoryGuard(storage: Pick<Storage, 'getItem' | 'setItem'>): HistoryGuard {
  return { async observe(owner, vault, entries, signal, removed = []) {
    const name = key(owner, vault.id)
    const keyVersion = vault.key_version ?? 1
    const wrapper = await digest(new TextEncoder().encode(JSON.stringify([keyVersion, vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key])))
    const marks: Record<string, Mark> = {}
    for (const entry of entries) {
      signal.throwIfAborted()
      marks[entry.id] = { revision: entry.revision, state: entry.state_version, keyVersion, removed: false,
        digest: await digest(fromBase64(entry.ciphertext, 17, 3 * 1024 * 1024 + 16)) }
    }
    signal.throwIfAborted()
    // Read immediately before the synchronous compare and write, including marks
    // committed by another tab while the ciphertext hashes were being computed.
    const commit = () => {
    signal.throwIfAborted()
    const old = read(storage.getItem(name))
    if (old) {
      if (keyVersion < old.keyVersion || (old.wrappers.includes(wrapper) && old.wrappers.at(-1) !== wrapper)) throw rollback()
      for (const [id, mark] of Object.entries(marks)) {
        const seen = old.entries[id]
        if (seen && (seen.removed || mark.revision < seen.revision || mark.state < seen.state ||
            (keyVersion === seen.keyVersion && mark.revision === seen.revision && mark.digest !== seen.digest))) throw rollback()
      }
    }
    const history: History = { version: 1, keyVersion, wrappers: old?.wrappers ?? [], entries: { ...old?.entries } }
    if (history.wrappers.at(-1) !== wrapper) history.wrappers.push(wrapper)
    for (const [id, mark] of Object.entries(history.entries)) {
      if (removed.includes(id)) history.entries[id] = { ...mark, removed: true }
    }
    Object.assign(history.entries, marks)
    if (history.wrappers.length > 1000 || Object.keys(history.entries).length > 20000) {
      throw new VaultDataError('Browser history reached its capacity. Review your backup, then reset browser history in Security Center.')
    }
    try { storage.setItem(name, JSON.stringify(history)) }
    catch { throw new VaultDataError('This browser could not save vault history. Free browser storage before trying again.') }
    }
    // Serialize commits across tabs where Web Locks is supported. The fallback
    // still checks immediately before the synchronous write.
    if (globalThis.navigator?.locks) await navigator.locks.request(name, { signal }, commit)
    else commit()
  } }
}
