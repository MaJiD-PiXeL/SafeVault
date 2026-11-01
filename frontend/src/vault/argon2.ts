import { argon2id } from 'hash-wasm'

// Fixed v1 profile; no server-controlled allocations or parameter negotiation.
export async function deriveArgon2id(password: Uint8Array, salt: Uint8Array): Promise<Uint8Array> {
  if (!password.length || password.length > 4096 || salt.length !== 16) throw new Error('Invalid key derivation input.')
  return argon2id({ password, salt, iterations: 3, parallelism: 4, memorySize: 65536, hashLength: 32, outputType: 'binary' })
}
