import { useState } from 'react'
import type { VaultController } from './controller'
import { hasDeviceUnlock } from './device'

export default function DeviceUnlockPanel({ controller }: { controller: VaultController }) {
  const state = controller.getSnapshot()
  if (!state.unlocked) return null
  return <DeviceUnlockForm key={`${state.ownerId}:${state.selectedId}:${state.lockEpoch}`} controller={controller} />
}

function DeviceUnlockForm({ controller }: { controller: VaultController }) {
  const state = controller.getSnapshot()
  const vault = state.vaults.find(item => item.id === state.selectedId)
  const enabled = Boolean(vault && state.ownerId && hasDeviceUnlock(state.ownerId, vault))
  const [password, setPassword] = useState('')
  const [saved, setSaved] = useState(false)
  if (!state.unlocked || !vault) return null
  return <section className="mt-8 border-t border-white/10 pt-6">
    <h3 className="text-sm font-semibold">Device unlock</h3>
    <p className="mt-3 text-xs leading-6 text-slate-400">Use your device's fingerprint, face recognition or PIN after account sign-in. Requires a browser and passkey provider with encryption support. An encrypted vault key stays in this browser; your master password is never saved. Your passkey provider may sync the passkey.</p>
    {enabled ? <button type="button" disabled={state.busy} onClick={() => { controller.disableDeviceUnlock(); setSaved(false) }} className="mt-4 rounded-xl border border-white/10 px-4 py-2.5 text-sm">Remove device unlock from this browser</button> : <form className="mt-4 space-y-4" onSubmit={event => { event.preventDefault(); const master = password; setPassword(''); void controller.enableDeviceUnlock(master).then(setSaved) }}>
      <label className="block text-xs text-slate-300">Current master password<input required type="password" autoComplete="off" maxLength={1024} value={password} onChange={event => setPassword(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm" /></label>
      <button disabled={state.busy} className="rounded-xl border border-white/10 px-4 py-2.5 text-sm disabled:opacity-50">Set up device unlock</button>
    </form>}
    {saved && <p role="status" className="mt-3 text-xs text-blue-300">Device unlock saved. Keep your master password and recovery key safe.</p>}
  </section>
}
