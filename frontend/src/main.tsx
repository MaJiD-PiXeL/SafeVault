import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { takeAccountLink } from './accountLink'
import { readFillRequest } from './vault/autofill'

const accountLink = takeAccountLink()
const initialFillRequest = readFillRequest(location.hash)
if (new URLSearchParams(location.hash.slice(1)).has('autofill')) history.replaceState(history.state, '', location.pathname + location.search)

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('/offline-shell.js', { updateViaCache: 'none' }).catch(() => {
      // The backup reader still works in this tab when caching is unavailable.
    })
  }, { once: true })
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App initialAccountLink={accountLink} initialFillRequest={initialFillRequest} />
  </StrictMode>,
)
