import { httpsOrigin } from './policy.js'

// The worker owns the entire operation; closing the popup cannot interrupt it.
export async function startFillRequest(api, vaultOrigin) {
  const [target] = await api.tabs.query({ active: true, currentWindow: true })
  const origin = httpsOrigin(target?.url)
  if (!origin || !Number.isInteger(target.id)) throw new Error('Open an HTTPS sign-in page first.')
  const token = crypto.randomUUID()
  const hash = new URLSearchParams({ autofill: api.runtime.id, token, origin })
  await api.storage.session.remove('pending')
  const source = await api.tabs.create({ url: `${vaultOrigin}/#${hash}`, active: false })
  if (!Number.isInteger(source.id)) throw new Error('Could not open the vault tab.')
  const pending = { token, origin, targetTab: target.id, sourceTab: source.id, expires: Date.now() + 120000 }
  // Commit routing before focus changes or any approval can be made.
  await api.storage.session.set({ pending })
  await api.tabs.update(source.id, { active: true })
  return { ok: true }
}
