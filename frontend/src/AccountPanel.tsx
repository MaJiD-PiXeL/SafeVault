import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { LogOut, ShieldCheck } from 'lucide-react'
import { accountApi, accountError } from './api'
import type { AccountUser, DeviceSession } from './api'
import { ForgotAccountPassword, RecoveryEmailSettings } from './AccountRecovery'

type Props = {
  user: AccountUser | null
  status: 'checking' | 'ready' | 'offline'
  onUserChange: (user: AccountUser | null) => void
  onRefresh: () => Promise<void>
  onLock: () => void
}

export default function AccountPanel({ user, status, onUserChange, onRefresh, onLock }: Props) {
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sessionData, setSessionData] = useState<{ ownerId: number; items: DeviceSession[] } | null>(null)
  const sessions = sessionData?.ownerId === user?.id ? sessionData?.items ?? [] : []
  const sessionsLoading = Boolean(user && sessionData?.ownerId !== user.id)

  useEffect(() => {
    if (!user) return
    const controller = new AbortController()
    accountApi.sessions(controller.signal).then((items) => setSessionData({ ownerId: user.id, items })).catch((reason: unknown) => {
      if (!controller.signal.aborted) { setError(accountError(reason)); setSessionData({ ownerId: user.id, items: [] }) }
    })
    return () => controller.abort()
  }, [user])

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || status !== 'ready') return
    setError('')
    if (mode === 'register' && password !== confirmation) { setError('Account passwords do not match.'); return }
    setBusy(true)
    try {
      const session = mode === 'register'
        ? await accountApi.register(username, password)
        : await accountApi.signIn(username, password)
      setUsername('')
      onUserChange(session.user)
    } catch (reason) { setError(accountError(reason)) }
    finally { setPassword(''); setConfirmation(''); setBusy(false) }
  }

  async function signOut() {
    onLock()
    setBusy(true)
    setError('')
    try { const result = await accountApi.signOut(); onUserChange(result.user) }
    catch (reason) { setError(accountError(reason)); await onRefresh() }
    finally { setBusy(false) }
  }

  async function revoke(id: string) {
    if (!user) return
    setBusy(true)
    setError('')
    try { await accountApi.revokeSession(id); setSessionData({ ownerId: user.id, items: await accountApi.sessions() }) }
    catch (reason) { setError(accountError(reason)); await onRefresh() }
    finally { setBusy(false) }
  }

  return (
    <section aria-labelledby="account-heading" className="mt-9 max-w-3xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
      <div className="flex items-center gap-3">
        <ShieldCheck className="text-blue-400" size={22} />
        <h2 id="account-heading" className="text-lg font-semibold">Your NEXORA account</h2>
      </div>
      {status === 'checking' && <p role="status" className="mt-5 text-sm text-slate-400">Checking your session...</p>}
      {status === 'offline' && <div className="mt-5 text-sm text-amber-300" role="status">Account service is unavailable. <button className="ml-2 underline" onClick={() => void onRefresh()}>Retry connection</button></div>}
      {error && <p role="alert" className="mt-5 rounded-xl border border-red-400/20 bg-red-400/5 p-3 text-sm text-red-300">{error}</p>}
      {user ? <>
        <div className="mt-6 flex flex-wrap items-center justify-between gap-4">
          <div><p className="font-medium">{user.username}</p><p className="mt-1 text-xs text-slate-400">Account session active · Vault unlock is separate</p></div>
          <button disabled={busy} onClick={() => void signOut()} className="flex items-center gap-2 rounded-xl border border-white/10 px-4 py-2.5 text-sm text-slate-300 disabled:opacity-50"><LogOut size={15} />Sign out</button>
        </div>
        <RecoveryEmailSettings />
        <h3 className="mt-8 border-t border-white/10 pt-6 text-sm font-semibold">Active browser sessions</h3>
        <p className="mt-2 text-xs leading-6 text-slate-400">Sessions expire after 30 minutes. You can end access from another browser here.</p>
        {sessionsLoading && <p role="status" className="mt-4 text-sm text-slate-400">Loading sessions...</p>}
        <ul className="mt-4 divide-y divide-white/10">
          {sessions.map((session) => <li key={session.id} className="flex flex-wrap items-center justify-between gap-3 py-4">
            <div><p className="text-sm">{session.current ? 'This browser' : 'Browser session'}</p><p className="mt-1 text-xs text-slate-500">Started {new Date(session.createdAt).toLocaleString('en-US')}</p><p className="mt-1 text-xs text-slate-500">Expires {new Date(session.expiresAt).toLocaleString('en-US')}</p></div>
            {session.current ? <span className="text-xs text-blue-300">Current session</span> : <button disabled={busy} onClick={() => void revoke(session.id)} className="rounded-lg border border-white/10 px-3 py-2 text-xs text-slate-300 disabled:opacity-50">Revoke access</button>}
          </li>)}
        </ul>
      </> : <>
        <p className="mt-4 text-sm leading-7 text-slate-400">Sign in to your account. Your vault master password will be set up separately on your device.</p>
        <div className="mt-6 flex gap-2" aria-label="Account actions">
          {(['login', 'register'] as const).map((value) => <button key={value} disabled={busy} aria-pressed={mode === value} onClick={() => { setMode(value); setError(''); setPassword(''); setConfirmation('') }} className={`rounded-lg px-4 py-2.5 text-sm ${mode === value ? 'bg-blue-500/15 text-blue-300' : 'text-slate-400 hover:bg-white/5'}`}>{value === 'login' ? 'Sign in' : 'Create account'}</button>)}
        </div>
        <form onSubmit={(event) => void submit(event)} className="mt-6 max-w-md space-y-5">
          <label className="block text-xs text-slate-300">Username
            <input required name="username" autoComplete="username" autoCapitalize="none" spellCheck={false} minLength={3} maxLength={50} pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]{2,49}" value={username} onChange={(event) => setUsername(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" aria-describedby="username-hint" />
            <span id="username-hint" className="mt-2 block text-[11px] text-slate-500">3–50 letters, numbers, dots, underscores or hyphens. Stored in lowercase.</span>
          </label>
          <label className="block text-xs text-slate-300">Account password
            <input required type="password" name="password" autoComplete={mode === 'register' ? 'new-password' : 'current-password'} minLength={mode === 'register' ? 12 : 1} maxLength={1024} value={password} onChange={(event) => setPassword(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" />
          </label>
          {mode === 'register' && <label className="block text-xs text-slate-300">Confirm account password
            <input required type="password" name="confirmation" autoComplete="new-password" maxLength={1024} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm outline-none focus:border-blue-400" />
          </label>}
          <p className="text-xs leading-6 text-slate-500">{mode === 'register' ? 'Use at least 12 characters and a password different from your vault master password. ' : ''}This form sends your account password to the account service.</p>
          <button disabled={busy || status !== 'ready'} className="w-full rounded-xl brand-primary px-5 py-3 text-sm font-semibold disabled:cursor-not-allowed disabled:opacity-50">{busy ? 'Please wait...' : mode === 'register' ? 'Create account' : 'Sign in'}</button>
        </form>
        {mode === 'login' && <ForgotAccountPassword />}
      </>}
      <p className="mt-7 border-t border-white/10 pt-5 text-xs leading-6 text-slate-500">Open All Passwords to create or unlock your encrypted vault. Guest accounts display sample items only.</p>
    </section>
  )
}
