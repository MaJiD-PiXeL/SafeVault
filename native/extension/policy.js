export function httpsOrigin(value) {
  try {
    const url = new URL(value)
    return url.protocol === 'https:' && !url.username && !url.password ? url.origin : null
  } catch { return null }
}

export function authorized(message, sender, pending, vaultOrigin, now = Date.now()) {
  try {
    return Boolean(pending && message && sender.frameId === 0 && new URL(sender.url).origin === vaultOrigin &&
      sender.tab?.id === pending.sourceTab && message.type === 'safevault.fill.v1' && message.token === pending.token &&
      message.origin === pending.origin && httpsOrigin(message.origin) === message.origin &&
      Number.isSafeInteger(pending.expires) && now < pending.expires && now >= pending.expires - 120000 &&
      typeof message.username === 'string' && message.username.length <= 65536 &&
      typeof message.password === 'string' && message.password.length <= 65536)
  } catch { return false }
}
