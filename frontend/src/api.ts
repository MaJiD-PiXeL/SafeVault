export async function checkHealth(signal: AbortSignal, baseUrl = import.meta.env?.VITE_API_BASE_URL ?? '/api') {
  const response = await fetch(`${baseUrl.replace(/\/$/, '')}/health/`, {
    signal: AbortSignal.any([signal, AbortSignal.timeout(5000)]),
  })
  if (!response.ok) throw new Error('API request failed')
  const data: unknown = await response.json()
  if (typeof data !== 'object' || data === null || !('status' in data) || data.status !== 'healthy') {
    throw new Error('Unexpected API health response')
  }
  return 'healthy'
}

export type AccountUser = { id: number; username: string }
export type AccountSession = { user: AccountUser | null; csrfToken: string }
export type DeviceSession = { id: string; createdAt: string; expiresAt: string; current: boolean }

export class ApiError extends Error {
  status: number

  constructor(message: string, status: number) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isAccountSession(value: unknown): value is AccountSession {
  return isObject(value) && typeof value.csrfToken === 'string' && /^[a-zA-Z0-9]{64}$/.test(value.csrfToken) &&
    (value.user === null || (isObject(value.user) && Number.isSafeInteger(value.user.id) && typeof value.user.username === 'string'))
}

export function createAccountApi(baseUrl = import.meta.env?.VITE_API_BASE_URL ?? '/api') {
  let csrfToken: string | null = null
  let csrfEpoch = 0
  const base = baseUrl.replace(/\/$/, '')

  async function request(path: string, method = 'GET', body?: unknown, signal?: AbortSignal, namespace = 'auth', timeoutMs = 10000) {
    const headers: Record<string, string> = { Accept: 'application/json' }
    if (method !== 'GET') {
      if (!csrfToken) await session(signal)
      headers['X-CSRFToken'] = csrfToken!
    }
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const [route, query] = path.split('?')
    const response = await fetch(`${base}/${namespace ? `${namespace}/` : ''}${route}/${query ? `?${query}` : ''}`, {
      method, credentials: 'include', cache: 'no-store', redirect: 'error', headers,
      signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]) : AbortSignal.timeout(timeoutMs),
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    })
    if (response.status === 204) return null
    let data: unknown
    try { data = await response.json() } catch { throw new ApiError('Unexpected server response.', response.status) }
    signal?.throwIfAborted()
    if (!response.ok) {
      if (isObject(data) && data.code === 'csrf_failed') csrfToken = null
      let message = 'Request could not be completed.'
      if (isObject(data)) {
        if (typeof data.detail === 'string') message = data.detail
        else {
          const errors = [data.username, data.password, data.non_field_errors].flat().filter((value) => typeof value === 'string')
          if (errors.length) message = errors.join(' ')
        }
      }
      throw new ApiError(message, response.status)
    }
    return data
  }

  function acceptSession(data: unknown, updateToken = true) {
    if (!isAccountSession(data)) throw new ApiError('Unexpected account response.', 502)
    if (updateToken) { csrfToken = data.csrfToken; csrfEpoch += 1 }
    return data
  }

  async function session(signal?: AbortSignal) {
    const epoch = csrfEpoch
    const data = await request('session', 'GET', undefined, signal)
    // A slow bootstrap must not replace the token rotated by a newer sign-in.
    return acceptSession(data, epoch === csrfEpoch)
  }

  return {
    session,
    async vaultRequest(path: string, method = 'GET', body?: unknown, signal?: AbortSignal, timeoutMs = 10000) {
      if (!/^[a-z0-9/-]+(?:\?page=[1-9][0-9]{0,2})?$/.test(path)) throw new ApiError('Invalid API path.', 400)
      return request(path, method, body, signal, '', Math.min(60000, Math.max(1000, timeoutMs)))
    },
    async signIn(username: string, password: string) {
      return acceptSession(await request('login', 'POST', { username, password }))
    },
    async register(username: string, password: string) {
      return acceptSession(await request('register', 'POST', { username, password }))
    },
    async signOut() { return acceptSession(await request('logout', 'POST')) },
    async sessions(signal?: AbortSignal): Promise<DeviceSession[]> {
      const data = await request('sessions', 'GET', undefined, signal)
      if (!isObject(data) || !Array.isArray(data.sessions) || !data.sessions.every((item) =>
        isObject(item) && typeof item.id === 'string' && /^[0-9a-f-]{36}$/.test(item.id) &&
        typeof item.createdAt === 'string' && Number.isFinite(Date.parse(item.createdAt)) &&
        typeof item.expiresAt === 'string' && Number.isFinite(Date.parse(item.expiresAt)) && typeof item.current === 'boolean')) {
        throw new ApiError('Unexpected sessions response.', 502)
      }
      return data.sessions as DeviceSession[]
    },
    async revokeSession(id: string) {
      if (!/^[0-9a-f-]{36}$/.test(id)) throw new ApiError('Invalid session identifier.', 400)
      await request(`sessions/${id}`, 'DELETE')
    },
  }
}

export const accountApi = createAccountApi()

export function accountError(error: unknown) {
  return error instanceof ApiError ? error.message : 'Unable to reach the server. Please try again.'
}
