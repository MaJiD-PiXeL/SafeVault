import { useEffect, useState } from 'react'
import { accountApi, accountError } from './api'

export default function SecondFactorPanel() {
  const [status, setStatus] = useState<{ enabled: boolean; recoveryCodesRemaining: number } | null>(null)
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(null)
  const [codes, setCodes] = useState<string[]>([])
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState(false)
  const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm'
  useEffect(() => {
    const abort = new AbortController()
    void accountApi.secondFactor(abort.signal).then(setStatus).catch((reason: unknown) => { if (!abort.signal.aborted) setError(accountError(reason)) })
    return () => abort.abort()
  }, [])

  async function refresh() {
    if (busy) return
    setBusy(true); setError('')
    try { const current = await accountApi.secondFactor(); setStatus(current); if (current.enabled) setSetup(null) }
    catch (reason) { setError(accountError(reason)); setStatus(null) }
    finally { setBusy(false) }
  }

  async function submit(action: 'begin' | 'confirm' | 'disable' | 'regenerate') {
    if (busy || !status) return
    setBusy(true); setError(''); setNotice('')
    try {
      if (action === 'disable') { await accountApi.disableSecondFactor(password, code); setCodes([]) }
      else if (action === 'confirm' || action === 'regenerate') { setCodes(await accountApi.confirmSecondFactor(password, code, action)); setSetup(null) }
      else setSetup(await accountApi.beginSecondFactor(password))
      setStatus(await accountApi.secondFactor())
    } catch (reason) {
      setError(accountError(reason))
      setStatus(null)
      try {
        const current = await accountApi.secondFactor()
        setStatus(current)
        if (current.enabled) {
          setSetup(null)
          if (action === 'confirm' || action === 'regenerate') setNotice('Two-step verification is enabled. If you did not receive recovery codes, generate new ones below using a fresh authenticator code. Previous recovery codes will be replaced.')
        } else if (action === 'disable') { setCodes([]); setNotice('Two-step verification is disabled.') }
      } catch { setNotice('The result could not be confirmed. Refresh verification status before trying another change.') }
    }
    finally { setPassword(''); setCode(''); setBusy(false) }
  }

  return <section className="mt-8 border-t border-white/10 pt-6">
    <h3 className="text-sm font-semibold">Two-step verification</h3>
    <p className="mt-2 text-xs leading-6 text-slate-400">{status?.enabled ? `Enabled · ${status.recoveryCodesRemaining} recovery codes remaining.` : 'Protect account sign-in with an authenticator app. Account email reset keeps this protection enabled.'}</p>
    {error && <p role="alert" className="mt-3 text-sm text-red-300">{error}</p>}
    {notice && <p role="status" className="mt-3 text-xs leading-6 text-amber-200">{notice}</p>}
    <button type="button" disabled={busy} className="mt-3 text-xs underline disabled:opacity-50" onClick={() => void refresh()}>Refresh verification status</button>
    {setup && <div className="mt-4 rounded-xl border border-blue-400/20 p-4 text-xs leading-6">
      <p>Add a time-based account in your authenticator using this setup key. Setup expires after 10 minutes. Keep this key private.</p>
      <code className="mt-3 block break-all select-all text-blue-200">{setup.secret}</code>
      <p className="mt-3">Enter a code from the authenticator and your account password to finish.</p>
      <button type="button" disabled={busy} className="mt-3 underline" onClick={() => { setSetup(null); setPassword(''); setCode('') }}>Cancel setup</button>
    </div>}
    {codes.length > 0 && <div className="mt-4 rounded-xl border border-amber-400/30 p-4 text-xs leading-6 text-amber-200">
      <p>Save these recovery codes outside your vault before leaving. Each code works once. They will not be shown again.</p>
      <pre className="mt-3 overflow-x-auto select-all">{codes.join('\n')}</pre>
      <button type="button" className="mt-3 underline" onClick={() => setCodes([])}>I saved my recovery codes</button>
    </div>}
    {status && codes.length === 0 && <form className="mt-5 max-w-md space-y-4" onSubmit={event => { event.preventDefault(); const value = ((event.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null)?.value; void submit(status.enabled ? value === 'disable' ? 'disable' : 'regenerate' : setup ? 'confirm' : 'begin') }}>
      <label className="block text-xs text-slate-300">Current account password<input required type="password" autoComplete="current-password" maxLength={1024} value={password} onChange={event => setPassword(event.target.value)} className={inputClass} /></label>
      {(setup || status.enabled) && <label className="block text-xs text-slate-300">Authenticator {status.enabled ? 'or recovery ' : ''}code<input required autoComplete="one-time-code" maxLength={64} value={code} onChange={event => setCode(event.target.value)} className={inputClass} /></label>}
      {status.enabled && <p className="text-xs leading-6 text-slate-400">Use your password and a fresh code to replace recovery codes or disable verification. Changes end other browser sessions. Generating codes invalidates all previous recovery codes.</p>}
      <button value="regenerate" disabled={busy} className="rounded-xl border border-white/10 px-4 py-2.5 text-sm disabled:opacity-50">{busy ? 'Please wait...' : status.enabled ? 'Generate new recovery codes' : setup ? 'Confirm and show recovery codes' : 'Set up authenticator'}</button>
      {status.enabled && <button value="disable" disabled={busy} className="ml-3 rounded-xl border border-red-400/20 px-4 py-2.5 text-sm text-red-200 disabled:opacity-50">Disable two-step verification</button>}
    </form>}
  </section>
}
