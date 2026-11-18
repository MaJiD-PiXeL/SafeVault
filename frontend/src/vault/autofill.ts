import type { EntryPayload } from './format.ts'
export type FillRequest = { extension: string; token: string; origin: string; created: number }
const extensionId = /^[a-p]{32}$/
const tokenId = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/

export function readFillRequest(hash: string): FillRequest | null {
  const params = new URLSearchParams(hash.slice(1))
  if (!params.has('autofill')) return null
  const extension = params.get('autofill') ?? ''
  const token = params.get('token') ?? ''
  const origin = params.get('origin') ?? ''
  try {
    const url = new URL(origin)
    if (extensionId.test(extension) && tokenId.test(token) && url.protocol === 'https:' && url.origin === origin &&
        Array.from(params).length === 3) return { extension, token, origin, created: Date.now() }
  } catch { /* malformed requests disclose nothing */ }
  return null
}

export function matchesFill(data: EntryPayload, origin: string) {
  if (data.schema_version !== 1) return false
  try { const url = new URL(data.website); return url.protocol === 'https:' && !url.username && !url.password && url.origin === origin }
  catch { return false }
}

export function pairedExtension(owner: number) {
  try { return localStorage.getItem(`safevault.extension.v1:${owner}`) ?? '' } catch { return '' }
}

export function pairExtension(owner: number, id: string) {
  if (id && !extensionId.test(id)) throw new Error('Enter the 32-letter ID shown by your installed SafeVault extension.')
  if (id) localStorage.setItem(`safevault.extension.v1:${owner}`, id)
  else localStorage.removeItem(`safevault.extension.v1:${owner}`)
}

export async function sendFill(owner: number, request: FillRequest, data: EntryPayload) {
  const now = Date.now()
  if (pairedExtension(owner) !== request.extension || now < request.created || now - request.created >= 120000 ||
      !matchesFill(data, request.origin) || data.schema_version !== 1) throw new Error('This fill request expired or is not paired with this account.')
  const runtime = (globalThis as typeof globalThis & { chrome?: { runtime?: { sendMessage: (id: string, message: unknown) => Promise<unknown> } } }).chrome?.runtime
  if (!runtime?.sendMessage) throw new Error('Install and pair the SafeVault extension in Chrome or Edge.')
  const result = await runtime.sendMessage(request.extension, { type: 'safevault.fill.v1', token: request.token,
    origin: request.origin, username: data.username, password: data.password })
  if (!result || typeof result !== 'object' || !('ok' in result) || result.ok !== true) throw new Error('Could not fill this page. The request may have expired, the tab changed, or the form is unsupported.')
}
