import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { accountApi, accountError } from './api'
import type { RecoveryEmail } from './api'
import type { AccountLink } from './accountLink'

const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400'
const buttonClass = 'rounded-xl brand-primary px-4 py-2.5 text-sm font-semibold disabled:opacity-50'

export function RecoveryEmailSettings() {
  const [address, setAddress] = useState<RecoveryEmail | null>(null)
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [notice, setNotice] = useState('')
  const [reload, setReload] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    accountApi.recoveryEmail(controller.signal).then((value) => {
      if (controller.signal.aborted) return
      setAddress(value)
      setEmail(value.email ?? '')
    }).catch((reason: unknown) => {
      if (!controller.signal.aborted) setError(accountError(reason))
    })
    return () => controller.abort()
  }, [reload])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    const accountPassword = password
    setPassword('')
    setBusy(true)
    setError('')
    setNotice('')
    try {
      await accountApi.enrollRecoveryEmail(email, accountPassword)
      setNotice('Verification link sent. Open your email to confirm this address.')
    } catch (reason) {
      setError(accountError(reason))
    } finally {
      setBusy(false)
    }
  }

  return <section aria-labelledby="recovery-email-heading" className="mt-8 border-t border-white/10 pt-6">
    <h3 id="recovery-email-heading" className="text-sm font-semibold">Recovery email</h3>
    {error && <p role="alert" className="mt-3 text-sm text-red-300">{error}</p>}
    {notice && <p role="status" className="mt-3 text-sm text-blue-300">{notice}</p>}
    {!address ? (error ? <button type="button" className="mt-3 text-sm underline" onClick={() => { setError(''); setReload(reload + 1) }}>Retry</button> : <p className="mt-3 text-sm text-slate-400">Loading recovery settings…</p>)
      : address.verified ? <p className="mt-3 break-all text-sm text-slate-300">{address.email} · Verified</p>
      : <>
        <p className="mt-3 text-sm text-slate-400">Verify a recovery email to reset your account password if you forget it. Your vault uses its separate master password.</p>
        {address.email && <p className="mt-2 break-all text-xs text-slate-400">Awaiting verification for {address.email}.</p>}
        <form onSubmit={(event) => void submit(event)} className="mt-4 max-w-md space-y-4">
          <label className="block text-xs text-slate-300">Recovery email
            <input required type="email" autoComplete="email" maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} className={inputClass} />
          </label>
          <label className="block text-xs text-slate-300">Current account password
            <input required type="password" autoComplete="current-password" maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} className={inputClass} />
          </label>
          <button disabled={busy} className={buttonClass}>{busy ? 'Sending…' : 'Send verification link'}</button>
          <button type="button" disabled={busy} className="ml-3 text-xs text-slate-400 underline" onClick={() => { setError(''); setReload(reload + 1) }}>Refresh status</button>
        </form>
      </>}
  </section>
}

export function ForgotAccountPassword() {
  const [expanded, setExpanded] = useState(false)
  const [username, setUsername] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sent, setSent] = useState(false)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setBusy(true)
    setError('')
    try {
      await accountApi.requestPasswordReset(username)
      setSent(true)
    } catch (reason) {
      setError(accountError(reason))
    } finally {
      setBusy(false)
    }
  }

  return <div className="mt-5 max-w-md">
    <button type="button" aria-expanded={expanded} onClick={() => setExpanded(!expanded)} className="text-sm text-blue-300 underline">Forgot your account password?</button>
    {expanded && (sent
      ? <p role="status" className="mt-4 text-sm text-slate-300">If this account has a verified recovery email, a reset link will be sent to it.</p>
      : <form onSubmit={(event) => void submit(event)} className="mt-4 space-y-4">
        {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
        <label className="block text-xs text-slate-300">Account username
          <input required minLength={3} maxLength={50} autoComplete="username" value={username} onChange={(event) => setUsername(event.target.value)} className={inputClass} />
        </label>
        <button disabled={busy} className={buttonClass}>{busy ? 'Requesting…' : 'Request reset link'}</button>
      </form>)}
  </div>
}

export function AccountLinkPanel({ link, onFinish }: { link: AccountLink; onFinish: (message?: string) => void }) {
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const verifying = link.action === 'verify'

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    if (!verifying && password !== confirmation) { setError('Account passwords do not match.'); return }
    const replacement = password
    setPassword('')
    setConfirmation('')
    setBusy(true)
    setError('')
    try {
      if (verifying) {
        await accountApi.verifyRecoveryEmail(link.username, link.token)
        onFinish('Recovery email verified.')
      } else {
        await accountApi.resetAccountPassword(link.username, link.token, replacement)
        onFinish('Account password reset. Sign in with your new account password.')
      }
    } catch (reason) {
      setError(accountError(reason))
    } finally {
      setBusy(false)
    }
  }

  return <section aria-labelledby="account-link-heading" className="mt-9 max-w-xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 id="account-link-heading" className="text-lg font-semibold">{verifying ? 'Verify recovery email' : 'Reset account password'}</h2>
    <p className="mt-3 text-sm text-slate-400">For account <strong className="break-all text-slate-200">{link.username}</strong></p>
    {!verifying && <p className="mt-3 text-sm text-slate-400">Use your vault master password to unlock your saved data after you sign in.</p>}
    <form onSubmit={(event) => void submit(event)} className="mt-5 space-y-4">
      {error && <p role="alert" className="text-sm text-red-300">{error}</p>}
      {!verifying && <>
        <label className="block text-xs text-slate-300">New account password
          <input required type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} className={inputClass} />
        </label>
        <label className="block text-xs text-slate-300">Confirm new account password
          <input required type="password" autoComplete="new-password" minLength={12} maxLength={1024} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className={inputClass} />
        </label>
      </>}
      <button disabled={busy} className={buttonClass}>{busy ? 'Please wait…' : verifying ? 'Verify email' : 'Reset account password'}</button>
      <button type="button" disabled={busy} className="ml-3 text-sm text-slate-400 underline" onClick={() => onFinish()}>Cancel</button>
    </form>
  </section>
}
