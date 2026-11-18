import { httpsOrigin } from './policy.js'

document.getElementById('extension').textContent = chrome.runtime.id
const status = document.getElementById('status')
const button = document.getElementById('fill')
const [tab] = await chrome.tabs.query({ active: true, currentWindow: true })
const origin = httpsOrigin(tab?.url)
document.getElementById('target').textContent = origin ? `Fill only on ${origin}` : 'Open an HTTPS sign-in page first.'
button.disabled = !origin
button.addEventListener('click', async () => {
  button.disabled = true
  try {
    const result = await chrome.runtime.sendMessage({ type: 'safevault.start-fill.v1' })
    if (!result?.ok) throw new Error('Could not open SafeVault.')
    status.textContent = 'Unlock your vault and approve one matching login within two minutes.'
  } catch { status.textContent = 'Could not open SafeVault. Try again.'; button.disabled = false }
})
