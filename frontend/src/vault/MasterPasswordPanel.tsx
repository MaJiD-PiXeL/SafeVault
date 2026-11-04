import { useState } from 'react'
import type { FormEvent } from 'react'
import type { VaultController } from './controller'

export default function MasterPasswordPanel({ controller, onUnlock }: { controller: VaultController; onUnlock: () => void }) {
  const state = controller.getSnapshot()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (state.busy || !state.unlocked) return
    setError('')
    if (next !== confirmation) { setError('New master passwords do not match.'); return }
    if (current === next) { setError('Choose a different master password.'); return }
    const oldPassword = current
    const newPassword = next
    setCurrent(''); setNext(''); setConfirmation('')
    await controller.changeMasterPassword(oldPassword, newPassword)
  }

  const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400'
  return <section aria-labelledby="master-password-heading" className="mt-6 max-w-2xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 id="master-password-heading" className="text-lg font-semibold">Change master password</h2>
    <p className="mt-3 text-sm leading-7 text-slate-400">Change how you unlock this vault. Your saved entries and Trash keep their existing encryption. Your account password stays the same.</p>
    {state.masterPasswordResult && <p role="status" className="mt-4 text-sm text-blue-300">{state.masterPasswordResult}</p>}
    {!state.unlocked ? <button onClick={onUnlock} className="mt-5 rounded-xl brand-primary px-5 py-3 text-sm">Unlock vault</button> : <form onSubmit={(event) => void submit(event)} className="mt-6 max-w-md space-y-5">
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      <fieldset disabled={state.busy} className="space-y-5 disabled:opacity-60">
        <label className="block text-xs text-slate-300">Current master password<input required type="password" autoComplete="off" spellCheck={false} maxLength={1024} value={current} onChange={(event) => setCurrent(event.target.value)} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">New master password<input required type="password" autoComplete="off" spellCheck={false} minLength={12} maxLength={1024} value={next} onChange={(event) => setNext(event.target.value)} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Confirm new master password<input required type="password" autoComplete="off" spellCheck={false} minLength={12} maxLength={1024} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className={inputClass} /></label>
        <p className="text-xs leading-6 text-slate-400">Use a unique passphrase of at least 12 characters. The vault locks after the change. Already unlocked devices keep access; downloaded backups keep their separate backup passwords.</p>
        <button className="w-full rounded-xl brand-primary px-5 py-3 text-sm font-semibold">{state.busy ? 'Changing master password...' : 'Change master password'}</button>
      </fieldset>
    </form>}
  </section>
}
