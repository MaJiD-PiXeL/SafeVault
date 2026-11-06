import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.tsx'
import { takeAccountLink } from './accountLink'

const accountLink = takeAccountLink()

if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('/offline-shell.js', { updateViaCache: 'none' }).catch(() => {
      // The backup reader still works in this tab when caching is unavailable.
    })
  }, { once: true })
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App initialAccountLink={accountLink} />
  </StrictMode>,
)
