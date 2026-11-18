import { vaultOrigin } from './config.js'
import { authorized, httpsOrigin } from './policy.js'
import { fillLogin } from './fill.js'
import { startFillRequest } from './routing.js'

let processing = false
chrome.runtime.onMessage.addListener((message, sender, reply) => {
  if (sender.id !== chrome.runtime.id || sender.url !== chrome.runtime.getURL('popup.html') ||
      message?.type !== 'safevault.start-fill.v1' || processing) { reply({ ok: false }); return false }
  processing = true
  void startFillRequest(chrome, vaultOrigin).then(reply).catch(() => reply({ ok: false }))
    .finally(() => { processing = false })
  return true
})

chrome.runtime.onMessageExternal.addListener((message, sender, reply) => {
  if (processing) { reply({ ok: false }); return false }
  processing = true
  void (async () => {
    const { pending } = await chrome.storage.session.get('pending')
    if (!authorized(message, sender, pending, vaultOrigin)) return { ok: false }
    // Claim once before any secret is injected. Concurrent messages cannot reuse it.
    await chrome.storage.session.remove('pending')
    const target = await chrome.tabs.get(pending.targetTab)
    if (httpsOrigin(target.url) !== pending.origin) return { ok: false }
    const result = await chrome.scripting.executeScript({ target: { tabId: pending.targetTab, frameIds: [0] },
      func: fillLogin, args: [pending.origin, message.username, message.password] })
    const ok = result.length === 1 && result[0].result === true
    if (ok) await chrome.tabs.update(pending.targetTab, { active: true })
    return { ok }
  })().then(reply).catch(() => reply({ ok: false })).finally(() => { processing = false })
  return true
})
