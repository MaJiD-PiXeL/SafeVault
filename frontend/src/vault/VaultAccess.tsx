import { useState } from 'react'
import type { FormEvent } from 'react'
import { LockKeyhole } from 'lucide-react'
import type { VaultController } from './controller'

export default function VaultAccess({ controller }: { controller: VaultController }) {
  const state = controller.getSnapshot()
  const [master, setMaster] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [localError, setLocalError] = useState('')
  const creating = state.loaded && state.vaults.length === 0

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (state.busy) return
    setLocalError('')
    if (creating && master !== confirmation) { setLocalError('Master passwords do not match.'); return }
    const value = master
    setMaster('')
    setConfirmation('')
    if (creating) await controller.create(value)
    else await controller.unlock(value)
  }

  return <section className="mt-9 max-w-2xl rounded-2xl border border-blue-400/15 bg-vault-surface p-6 sm:p-8" aria-labelledby="unlock-heading">
    <LockKeyhole size={28} className="text-blue-400" />
    <h2 id="unlock-heading" className="mt-5 text-xl font-semibold">{creating ? 'Create your encrypted vault' : 'Your vault is locked'}</h2>
    <p className="mt-3 text-sm leading-7 text-slate-400">Your master password stays on this device. It unlocks your vault separately from your NEXORA account.</p>
    {(localError || state.error) && <p role="alert" className="mt-4 text-sm text-red-300">{localError || state.error}</p>}
    {!state.loaded ? <button disabled={state.busy} onClick={() => void controller.load()} className="mt-6 rounded-xl brand-primary px-5 py-3 text-sm disabled:opacity-50">{state.busy ? 'Loading vault...' : 'Load vault'}</button> : <>
      {state.vaults.length > 1 && <label className="mt-5 block text-sm text-slate-300">Vault<select aria-label="Select vault" value={state.selectedId ?? ''} disabled={state.busy} onChange={(event) => controller.select(event.target.value)} className="mt-2 block w-full rounded-lg bg-vault-raised p-3">{state.vaults.map((vault, index) => <option key={vault.id} value={vault.id}>Personal vault {index + 1}</option>)}</select></label>}
      <form className="mt-6 max-w-md space-y-5" onSubmit={(event) => void submit(event)}>
        <label className="block text-xs text-slate-300">Master password
          <input required type="password" autoComplete="off" spellCheck={false} minLength={creating ? 12 : 1} maxLength={1024} value={master} disabled={state.busy} onChange={(event) => setMaster(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" />
        </label>
        {creating && <label className="block text-xs text-slate-300">Confirm master password<input required type="password" autoComplete="off" maxLength={1024} value={confirmation} disabled={state.busy} onChange={(event) => setConfirmation(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" /></label>}
        {creating && <p className="text-xs leading-6 text-slate-400">Use a unique passphrase of at least 12 characters, different from your account password. Keep it safe: account recovery cannot recover your vault key.</p>}
        <button disabled={state.busy} className="w-full rounded-xl brand-primary px-5 py-3 text-sm font-semibold disabled:opacity-50">{state.busy ? 'Deriving your key...' : creating ? 'Create encrypted vault' : 'Unlock vault'}</button>
      </form>
      <button disabled={state.busy} onClick={() => void controller.load()} className="mt-5 text-xs text-slate-400 underline">Refresh vault list</button>
    </>}
    <p className="mt-6 border-t border-white/10 pt-4 text-xs leading-6 text-amber-200/70">Development build. Independent security audit pending; use test credentials.</p>
  </section>
}
