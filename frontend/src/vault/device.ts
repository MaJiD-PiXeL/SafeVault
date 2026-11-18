import { fromBase64, object, toBase64, UUID, VaultDataError } from './format.ts'
import type { VaultMetadata } from './format.ts'
import { importDataKey } from './crypto.ts'

type DeviceRecord = { version: 1; binding: string; credential: string; salt: string; nonce: string; wrapped: string }
type PRFExtensions = AuthenticationExtensionsClientInputs & { prf: { eval?: { first: Uint8Array<ArrayBuffer> } } }
type PRFResult = AuthenticationExtensionsClientOutputs & { prf?: { enabled?: boolean; results?: { first: ArrayBuffer } } }
const prefix = 'safevault.device.v1:'

function storageKey(owner: number, vault: VaultMetadata) {
  if (!Number.isSafeInteger(owner) || owner < 1 || !UUID.test(vault.id)) throw new VaultDataError()
  return `${prefix}${owner}:${vault.id}`
}

export async function deviceBinding(owner: number, vault: VaultMetadata) {
  storageKey(owner, vault)
  const bytes = new TextEncoder().encode(JSON.stringify([location.origin, owner, vault.id, vault.key_version ?? 1,
    vault.kdf_salt, vault.wrap_nonce, vault.wrapped_key]))
  return toBase64(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)))
}

export function hasDeviceUnlock(owner: number, vault: VaultMetadata) {
  try { return localStorage.getItem(storageKey(owner, vault)) !== null } catch { return false }
}

export function forgetDeviceUnlock(owner: number, vault: VaultMetadata) {
  localStorage.removeItem(storageKey(owner, vault))
}

function readRecord(owner: number, vault: VaultMetadata): DeviceRecord {
  try {
    const raw = localStorage.getItem(storageKey(owner, vault))
    if (!raw || raw.length > 4096) throw new Error()
    const record: unknown = JSON.parse(raw)
    if (!object(record) || record.version !== 1) throw new Error()
    fromBase64(record.binding, 32); fromBase64(record.credential, 1, 1024); fromBase64(record.salt, 32)
    fromBase64(record.nonce, 12); fromBase64(record.wrapped, 48)
    return record as DeviceRecord
  } catch { throw new VaultDataError('Device unlock is unavailable. Use your master password and set it up again.') }
}

async function prfKey(credential: Uint8Array<ArrayBuffer>, salt: Uint8Array<ArrayBuffer>, signal: AbortSignal) {
  const result = await navigator.credentials.get({ signal, publicKey: {
    challenge: crypto.getRandomValues(new Uint8Array(32)), timeout: 60000,
    allowCredentials: [{ type: 'public-key', id: credential }], userVerification: 'required',
    extensions: { prf: { eval: { first: salt } } } as PRFExtensions,
  } }) as PublicKeyCredential | null
  signal.throwIfAborted()
  const output = (result?.getClientExtensionResults() as PRFResult | undefined)?.prf?.results?.first
  if (!output || output.byteLength !== 32) throw new VaultDataError('This device does not support encrypted device unlock. Use your master password.')
  const bytes = new Uint8Array(output)
  try { return await importDataKey(bytes) } finally { bytes.fill(0) }
}

export async function saveDeviceUnlock(owner: number, vault: VaultMetadata, rawKey: Uint8Array<ArrayBuffer>, signal: AbortSignal) {
  if (!globalThis.PublicKeyCredential || !navigator.credentials) throw new VaultDataError('Device unlock is unavailable in this browser.')
  const created = await navigator.credentials.create({ signal, publicKey: {
    rp: { name: 'NEXORA SafeVault' },
    user: { id: crypto.getRandomValues(new Uint8Array(32)), name: 'SafeVault device unlock', displayName: 'SafeVault device unlock' },
    challenge: crypto.getRandomValues(new Uint8Array(32)),
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
    authenticatorSelection: { authenticatorAttachment: 'platform', residentKey: 'required', userVerification: 'required' },
    attestation: 'none', timeout: 60000, extensions: { prf: {} } as PRFExtensions,
  } }) as PublicKeyCredential | null
  signal.throwIfAborted()
  if (!created || !(created.getClientExtensionResults() as PRFResult).prf?.enabled) {
    throw new VaultDataError('Encrypted device unlock is not supported. Continue using your master password.')
  }
  const salt = crypto.getRandomValues(new Uint8Array(32))
  const key = await prfKey(new Uint8Array(created.rawId), salt, signal)
  const binding = await deviceBinding(owner, vault)
  const nonce = crypto.getRandomValues(new Uint8Array(12))
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
    additionalData: fromBase64(binding, 32), tagLength: 128 }, key, rawKey)
  signal.throwIfAborted()
  const record: DeviceRecord = { version: 1, binding, credential: toBase64(new Uint8Array(created.rawId)),
    salt: toBase64(salt), nonce: toBase64(nonce), wrapped: toBase64(new Uint8Array(wrapped)) }
  try { localStorage.setItem(storageKey(owner, vault), JSON.stringify(record)) }
  catch { throw new VaultDataError('This browser could not save encrypted device unlock.') }
}

export async function openDeviceUnlock(owner: number, vault: VaultMetadata, signal: AbortSignal) {
  const record = readRecord(owner, vault)
  if (record.binding !== await deviceBinding(owner, vault)) throw new VaultDataError('The vault password or encryption key changed. Use your master password and set up device unlock again.')
  const key = await prfKey(fromBase64(record.credential, 1, 1024), fromBase64(record.salt, 32), signal)
  let bytes: Uint8Array<ArrayBuffer> | undefined
  try {
    bytes = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromBase64(record.nonce, 12),
      additionalData: fromBase64(record.binding, 32), tagLength: 128 }, key, fromBase64(record.wrapped, 48)))
    signal.throwIfAborted()
    return await importDataKey(bytes)
  } catch { signal.throwIfAborted(); throw new VaultDataError('Device unlock could not authenticate this vault. Use your master password.') }
  finally { bytes?.fill(0) }
}
