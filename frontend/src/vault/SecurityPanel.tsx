import { useState } from 'react'
import type { VaultController } from './controller'
import DeviceUnlockPanel from './DeviceUnlockPanel'
import { ExtensionPairing } from './AutofillPanel'
import { resetBrowserHistory } from './history'

export default function SecurityPanel({ controller, signedIn }: { controller: VaultController; signedIn: boolean }) {
  const state = controller.getSnapshot()
  const [seconds, setSeconds] = useState(state.preferences.auto_lock_seconds)
  const [hidden, setHidden] = useState(state.preferences.lock_on_hidden)
  const [saved, setSaved] = useState(false)
  const [resetConfirmed, setResetConfirmed] = useState(false)
  const [historyResult, setHistoryResult] = useState('')
  return <section className="mt-9 max-w-2xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 className="text-lg font-semibold">Vault security</h2>
    {!signedIn ? <p className="mt-4 text-sm text-slate-400">Sign in to manage your vault security settings.</p> : <>
      <p className="mt-3 text-sm leading-7 text-slate-400">Sensitive entry fields use client-side AES-256-GCM. Your master password derives a wrapping key using Argon2id.</p>
      <label className="mt-6 block text-sm text-slate-300">Lock after inactivity<select value={seconds} onChange={(event) => { setSeconds(Number(event.target.value)); setSaved(false) }} className="mt-2 block w-full rounded-xl border border-white/10 bg-vault-raised p-3">{[60, 300, 600, 900, 1800, 3600].map((value) => <option key={value} value={value}>{value / 60} minutes</option>)}</select></label>
      <label className="mt-5 flex items-center gap-3 text-sm text-slate-300"><input type="checkbox" checked={hidden} onChange={(event) => { setHidden(event.target.checked); setSaved(false) }} />Lock when this tab is hidden</label>
      <button disabled={state.busy || !state.loaded} onClick={async () => { if (await controller.updatePreferences({ auto_lock_seconds: seconds, lock_on_hidden: hidden })) setSaved(true) }} className="mt-6 rounded-xl brand-primary px-5 py-3 text-sm disabled:opacity-50">Save security settings</button>
      {saved && <p role="status" className="mt-4 text-sm text-blue-300">Security settings saved.</p>}
      <DeviceUnlockPanel controller={controller} />
      {state.ownerId !== null && <ExtensionPairing key={state.ownerId} owner={state.ownerId} />}
      {state.ownerId !== null && state.selectedId && <section className="mt-8 border-t border-white/10 pt-6">
        <h3 className="text-sm font-semibold">Browser vault history</h3>
        <p className="mt-3 text-xs leading-6 text-slate-400">This browser remembers versions and encrypted content it has already seen. Reset only after verifying an intentional server restore. Resetting removes this browser's ability to detect earlier content being replayed.</p>
        <label className="mt-4 flex gap-3 text-xs leading-6"><input type="checkbox" checked={resetConfirmed} onChange={event => setResetConfirmed(event.target.checked)} />I verified my backup and intend to trust the next server snapshot.</label>
        <button type="button" disabled={!resetConfirmed || state.busy} onClick={() => { try { resetBrowserHistory(state.ownerId!, state.selectedId!); controller.forgetOffline(); setResetConfirmed(false); setHistoryResult('Browser history reset. Unlock to verify the next snapshot.') } catch { setHistoryResult('Browser history could not be reset.') } }} className="mt-4 rounded-xl border border-white/10 px-4 py-2.5 text-xs disabled:opacity-50">Reset history and lock vault</button>
        {historyResult && <p role="status" className="mt-3 text-xs text-blue-300">{historyResult}</p>}
      </section>}
      {state.error && <p role="alert" className="mt-4 text-sm text-red-300">{state.error}</p>}
      <p className="mt-6 text-xs leading-6 text-amber-200/70">Independent security audit pending. Offline backups are read-only.</p>
    </>}
  </section>
}
