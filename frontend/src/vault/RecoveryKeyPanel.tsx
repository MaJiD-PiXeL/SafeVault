import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import type { VaultController } from './controller'

export default function RecoveryKeyPanel({ controller, onUnlock }: { controller: VaultController; onUnlock: () => void }) {
  const state = controller.getSnapshot()
  const active = Boolean(state.vaults.find((vault) => vault.id === state.selectedId)?.recovery)
  const [mode, setMode] = useState<'generate' | 'disable' | null>(null)
  const [master, setMaster] = useState('')
  useEffect(() => () => controller.cancelRecoveryDraft(), [controller])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (state.busy) return
    const password = master
    setMaster('')
    setMode(null)
    if (mode === 'disable') await controller.disableRecovery(password)
    else if (mode === 'generate') await controller.prepareRecovery(password)
  }

  return <section aria-labelledby="vault-recovery-key-heading" className="mt-6 max-w-2xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 id="vault-recovery-key-heading" className="text-lg font-semibold">Vault recovery key</h2>
    <p className="mt-3 text-sm leading-7 text-slate-400">If you forget your master password, a recovery key lets you set a new one after you sign in. Save it somewhere you can reach without this vault.</p>
    {state.recoveryResult && <p role="status" className="mt-4 text-sm text-blue-300">{state.recoveryResult}</p>}
    {!state.unlocked ? <button onClick={onUnlock} className="mt-5 rounded-xl brand-primary px-5 py-3 text-sm">Unlock vault</button>
      : state.recoveryCode ? <div className="mt-5 space-y-4">
        <p className="text-sm text-slate-300">Copy or write down this entire key now. It is shown only once. {active ? 'Activating it replaces the previous recovery key.' : 'It will not work until you activate it.'}</p>
        <code className="block select-all break-all rounded-xl border border-white/10 bg-black/20 p-4 text-sm text-blue-200">{state.recoveryCode}</code>
        <div className="flex flex-wrap gap-3">
          <button disabled={state.busy} onClick={() => void controller.confirmRecovery()} className="rounded-xl brand-primary px-5 py-3 text-sm">I saved it — activate key</button>
          <button disabled={state.busy} onClick={controller.cancelRecoveryDraft} className="rounded-xl border border-white/10 px-5 py-3 text-sm">Cancel</button>
        </div>
      </div> : mode ? <form onSubmit={(event) => void submit(event)} className="mt-5 max-w-md space-y-4">
        <label className="block text-xs text-slate-300">Current master password
          <input required type="password" autoComplete="off" maxLength={1024} value={master} disabled={state.busy} onChange={(event) => setMaster(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" />
        </label>
        <div className="flex flex-wrap gap-3">
          <button disabled={state.busy} className="rounded-xl brand-primary px-5 py-3 text-sm">{mode === 'disable' ? 'Disable recovery key' : 'Generate recovery key'}</button>
          <button type="button" onClick={() => { setMode(null); setMaster('') }} className="rounded-xl border border-white/10 px-5 py-3 text-sm">Cancel</button>
        </div>
      </form> : <div className="mt-5 flex flex-wrap items-center gap-3">
        <button disabled={state.busy} onClick={() => setMode('generate')} className="rounded-xl brand-primary px-5 py-3 text-sm disabled:opacity-50">{active ? 'Replace recovery key' : 'Set up recovery key'}</button>
        {active && <button disabled={state.busy} onClick={() => setMode('disable')} className="rounded-xl border border-white/10 px-5 py-3 text-sm disabled:opacity-50">Disable</button>}
      </div>}
  </section>
}
