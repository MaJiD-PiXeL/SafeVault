import { useState } from 'react'
import type { FormEvent } from 'react'
import type { VaultController } from './controller'

export default function MasterPasswordPanel({ controller, onUnlock, rotate = false }: { controller: VaultController; onUnlock: () => void; rotate?: boolean }) {
  const state = controller.getSnapshot()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [error, setError] = useState('')
  const [rotationOpen, setRotationOpen] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (state.busy || !state.unlocked) return
    setError('')
    if (next !== confirmation) { setError('New master passwords do not match.'); return }
    if (current === next) { setError('Choose a different master password.'); return }
    const oldPassword = current
    const newPassword = next
    setCurrent(''); setNext(''); setConfirmation('')
    if (rotate) await controller.rotateKey(oldPassword, newPassword)
    else await controller.changeMasterPassword(oldPassword, newPassword)
  }

  const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400'
  const heading = rotate ? 'Rotate vault encryption key' : 'Change master password'
  const headingId = rotate ? 'key-rotation-heading' : 'master-password-heading'
  const result = rotate ? state.keyRotationResult : state.masterPasswordResult
  return <section aria-labelledby={headingId} className="mt-6 max-w-2xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 id={headingId} className="text-lg font-semibold">{heading}</h2>
    <p className="mt-3 text-sm leading-7 text-slate-400">{rotate
      ? 'Re-encrypt all saved entries and Trash with a fresh key and set a new master password. Use this if you suspect someone obtained your vault key or an old copy of your vault.'
      : 'Change how you unlock this vault. Your saved entries and Trash keep their existing encryption. Your account password stays the same.'}</p>
    {result && <p role="status" className="mt-4 text-sm text-blue-300">{result}</p>}
    {!state.unlocked ? <button onClick={onUnlock} className="mt-5 rounded-xl brand-primary px-5 py-3 text-sm">Unlock vault</button>
      : rotate && !rotationOpen ? <button onClick={() => setRotationOpen(true)} disabled={state.busy} className="mt-5 rounded-xl border border-white/10 px-5 py-3 text-sm disabled:opacity-50">Set up key rotation</button>
      : <form onSubmit={(event) => void submit(event)} className="mt-6 max-w-md space-y-5">
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      <fieldset disabled={state.busy} className="space-y-5 disabled:opacity-60">
        <label className="block text-xs text-slate-300">Current master password<input required type="password" autoComplete="off" spellCheck={false} maxLength={1024} value={current} onChange={(event) => setCurrent(event.target.value)} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">New master password<input required type="password" autoComplete="off" spellCheck={false} minLength={12} maxLength={1024} value={next} onChange={(event) => setNext(event.target.value)} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Confirm new master password<input required type="password" autoComplete="off" spellCheck={false} minLength={12} maxLength={1024} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className={inputClass} /></label>
        <p className="text-xs leading-6 text-slate-400">{rotate
          ? 'Other devices will need the new master password. Rotation disables your vault recovery key. Downloaded backups keep their own passwords, and rotation cannot protect copies someone already obtained.'
          : 'Use a unique passphrase of at least 12 characters. The vault locks after the change. Already unlocked devices keep access; downloaded backups keep their separate backup passwords.'}</p>
        <button className="w-full rounded-xl brand-primary px-5 py-3 text-sm font-semibold">{state.busy ? (rotate ? 'Rotating encryption key...' : 'Changing master password...') : heading}</button>
      </fieldset>
    </form>}
  </section>
}
