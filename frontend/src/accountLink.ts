export type AccountLink = { action: 'verify' | 'reset'; username: string; token: string }

export function readAccountLink(hash: string) {
  const params = new URLSearchParams(hash.slice(1))
  if (!params.has('account-action')) return null
  const action = params.get('account-action')
  const username = params.get('username') ?? ''
  const token = params.get('token') ?? ''
  if ((action !== 'verify' && action !== 'reset') ||
      !/^[a-z0-9][a-z0-9_.-]{2,49}$/.test(username) ||
      !/^[0-9a-z]{1,13}-[0-9a-f]{32}$/.test(token) ||
      Array.from(params).length !== 3) return { valid: false } as const
  return { valid: true, link: { action, username, token } satisfies AccountLink } as const
}

export function takeAccountLink() {
  const result = readAccountLink(window.location.hash)
  if (result) window.history.replaceState(window.history.state, '', window.location.pathname + window.location.search)
  return result
}
