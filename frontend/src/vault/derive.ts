import { VaultDataError } from './format'

export function deriveInWorker(password: string, salt: Uint8Array, signal: AbortSignal): Promise<Uint8Array> {
  signal.throwIfAborted()
  return new Promise((resolve, reject) => {
    const worker = new Worker(new URL('./argon2.worker.ts', import.meta.url), { type: 'module' })
    const passwordBytes = new TextEncoder().encode(password)
    const finish = () => { worker.terminate(); signal.removeEventListener('abort', abort); globalThis.clearTimeout(timeout) }
    const abort = () => { finish(); reject(new DOMException('Vault locked.', 'AbortError')) }
    const timeout = globalThis.setTimeout(() => { finish(); reject(new VaultDataError('Key derivation timed out. Try a device with more available memory.')) }, 60000)
    signal.addEventListener('abort', abort, { once: true })
    worker.onmessage = (event: MessageEvent<{ key?: Uint8Array }>) => {
      finish()
      if (event.data.key instanceof Uint8Array && event.data.key.length === 32) resolve(event.data.key)
      else reject(new VaultDataError('Key derivation failed in this browser.'))
    }
    worker.onerror = () => { finish(); reject(new VaultDataError('Key derivation failed in this browser.')) }
    try { worker.postMessage({ password: passwordBytes, salt }, [passwordBytes.buffer]) }
    catch { passwordBytes.fill(0); finish(); reject(new VaultDataError('Key derivation could not start in this browser.')) }
  })
}
