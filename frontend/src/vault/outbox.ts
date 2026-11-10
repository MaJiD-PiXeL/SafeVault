import { object, readKeyVersion, UUID, validateEnvelope } from './format.ts'
import type { EncryptedEntry } from './format.ts'

export type TrashAction = 'move' | 'restore'
export type PendingWrite = { keyVersion: number; envelope: EncryptedEntry } & (
  { kind?: undefined } | { kind: TrashAction; operationId: string }
)
export type Outbox = {
  list: (ownerId: number, vaultId: string) => Promise<PendingWrite[]>
  change: (ownerId: number, vaultId: string, before: PendingWrite | null, after: PendingWrite | null) => Promise<boolean>
}

const STORE = 'pending-saves'
const MAX_CHANGES = 32
const MAX_CIPHERTEXT = 16 * 1024 * 1024

export class OutboxError extends Error {
  readonly unavailable: boolean

  constructor(message = 'Encrypted local storage is unavailable on this device.', unavailable = false) {
    super(message)
    this.unavailable = unavailable
  }
}

export function pendingWriteId(write: PendingWrite) {
  return write.kind ? write.operationId : write.envelope.nonce
}

function readWrite(value: unknown, vaultId: string): PendingWrite {
  if (!object(value)) throw new OutboxError()
  const keyVersion = readKeyVersion(value.keyVersion)
  const envelope = validateEnvelope(value.envelope, vaultId)
  if (value.kind === undefined && value.operationId === undefined) return { keyVersion, envelope }
  if ((value.kind !== 'move' && value.kind !== 'restore') || typeof value.operationId !== 'string' || !UUID.test(value.operationId) ||
      (envelope.deleted_at !== null) !== (value.kind === 'restore') || envelope.state_version >= 2147483647) throw new OutboxError()
  return { keyVersion, envelope, kind: value.kind, operationId: value.operationId }
}

export function createOutbox(): Outbox {
  async function transaction<T>(mode: IDBTransactionMode, action: (store: IDBObjectStore, finish: (value: T) => void, fail: (error: unknown) => void) => void): Promise<T> {
    const db = await new Promise<IDBDatabase>((resolve, reject) => {
      try {
        // A v1 client reads every row as an entry save. Upgrade before writing Trash actions.
        const request = indexedDB.open('nexora-safevault-outbox', 2)
        let blocked = false
        request.onupgradeneeded = (event) => { if (event.oldVersion === 0) request.result.createObjectStore(STORE) }
        request.onblocked = () => {
          blocked = true
          reject(new OutboxError('Close other SafeVault tabs to update encrypted local storage.'))
        }
        request.onsuccess = () => { if (blocked) request.result.close(); else resolve(request.result) }
        request.onerror = () => reject(new OutboxError(undefined, true))
      } catch { reject(new OutboxError(undefined, true)) }
    })
    try {
      return await new Promise<T>((resolve, reject) => {
        try {
          const tx = db.transaction(STORE, mode, mode === 'readwrite' ? { durability: 'strict' } : undefined)
          let result: T
          const fail = (error: unknown) => { reject(error); tx.abort() }
          tx.oncomplete = () => resolve(result)
          tx.onabort = () => reject(new OutboxError())
          action(tx.objectStore(STORE), (value) => { result = value }, fail)
        } catch { reject(new OutboxError()) }
      })
    } finally { db.close() }
  }

  function records(store: IDBObjectStore, ownerId: number, vaultId: string, onRows: (rows: PendingWrite[]) => void, fail: (error: unknown) => void) {
    const request = store.getAll(IDBKeyRange.bound([ownerId, vaultId], [ownerId, vaultId, []]), MAX_CHANGES + 1)
    request.onsuccess = () => {
      try {
        const rows = (request.result as unknown[]).map((row) => readWrite(row, vaultId))
        if (rows.length > MAX_CHANGES || rows.reduce((size, row) => size + row.envelope.ciphertext.length, 0) > MAX_CIPHERTEXT) throw new OutboxError()
        onRows(rows)
      } catch (error) { fail(error instanceof OutboxError ? error : new OutboxError()) }
    }
  }

  return {
    list: (ownerId, vaultId) => transaction('readonly', (store, finish, fail) => records(store, ownerId, vaultId, finish, fail)),
    change: (ownerId, vaultId, before, after) => transaction('readwrite', (store, finish, fail) => {
      records(store, ownerId, vaultId, (rows) => {
        const previous = before && rows.find((row) => row.envelope.id === before.envelope.id)
        if ((before && (!previous || pendingWriteId(previous) !== pendingWriteId(before))) ||
            (after && rows.some((row) => row !== previous && row.envelope.id === after.envelope.id))) {
          finish(false)
          return
        }
        const size = rows.reduce((sum, row) => sum + (row === previous ? 0 : row.envelope.ciphertext.length), 0)
        if (after && (rows.length - Number(Boolean(previous)) >= MAX_CHANGES || size + after.envelope.ciphertext.length > MAX_CIPHERTEXT)) {
          throw new OutboxError('Encrypted local storage is full. Sync or discard a change before saving another.')
        }
        if (before) store.delete([ownerId, vaultId, before.envelope.id])
        if (after) store.add(after, [ownerId, vaultId, after.envelope.id])
        finish(true)
      }, fail)
    }),
  }
}
