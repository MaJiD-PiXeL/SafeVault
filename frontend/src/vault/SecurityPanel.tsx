import { useState } from 'react'
import type { VaultController } from './controller'

export default function SecurityPanel({ controller, signedIn }: { controller: VaultController; signedIn: boolean }) {
  const state = controller.getSnapshot()
  const [seconds, setSeconds] = useState(state.preferences.auto_lock_seconds)
  const [hidden, setHidden] = useState(state.preferences.lock_on_hidden)
  const [saved, setSaved] = useState(false)
  return <section className="mt-9 max-w-2xl rounded-2xl border border-white/10 bg-[#0c0f15] p-6 sm:p-8">
    <h2 className="text-lg font-semibold">Vault security</h2>
    {!signedIn ? <p className="mt-4 text-sm text-slate-400">Sign in to manage your vault security settings.</p> : <>
      <p className="mt-3 text-sm leading-7 text-slate-400">Sensitive entry fields use client-side AES-256-GCM. Your master password derives a wrapping key using Argon2id.</p>
      <label className="mt-6 block text-sm text-slate-300">Lock after inactivity<select value={seconds} onChange={(event) => { setSeconds(Number(event.target.value)); setSaved(false) }} className="mt-2 block w-full rounded-xl border border-white/10 bg-[#101725] p-3">{[60, 300, 600, 900, 1800, 3600].map((value) => <option key={value} value={value}>{value / 60} minutes</option>)}</select></label>
      <label className="mt-5 flex items-center gap-3 text-sm text-slate-300"><input type="checkbox" checked={hidden} onChange={(event) => { setHidden(event.target.checked); setSaved(false) }} />Lock when this tab is hidden</label>
      <button disabled={state.busy || !state.loaded} onClick={async () => { if (await controller.updatePreferences({ auto_lock_seconds: seconds, lock_on_hidden: hidden })) setSaved(true) }} className="mt-6 rounded-xl bg-blue-600 px-5 py-3 text-sm disabled:opacity-50">Save security settings</button>
      {saved && <p role="status" className="mt-4 text-sm text-blue-300">Security settings saved.</p>}
      {state.error && <p role="alert" className="mt-4 text-sm text-red-300">{state.error}</p>}
      <p className="mt-6 text-xs leading-6 text-amber-200/70">Independent security audit pending. Offline access, master-password changes and recovery keys are not available in this build.</p>
    </>}
  </section>
}
