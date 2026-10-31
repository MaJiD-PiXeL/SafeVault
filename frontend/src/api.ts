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
