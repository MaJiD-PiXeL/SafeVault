import { deriveArgon2id } from './argon2'

self.onmessage = async (event: MessageEvent<{ password: Uint8Array; salt: Uint8Array }>) => {
  const { password, salt } = event.data
  try {
    const result = await deriveArgon2id(password, salt)
    self.postMessage({ key: result }, { transfer: [result.buffer] })
  } catch {
    self.postMessage({ error: 'Key derivation failed.' })
  } finally { password.fill(0) }
}
