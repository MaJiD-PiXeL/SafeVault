import { useCallback, useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { BackupError, MAX_BACKUP_FILE_BYTES, openBackup } from './backup'
import type { BackupContent } from './backup'
import { deriveInWorker } from './derive'
import { ENTRY_LABELS, entryKind, entrySummary } from './format'
import type { EntryPayload } from './format'

const IDLE_LIMIT_MS = 5 * 60 * 1000
const PAGE_SIZE = 25

function EntryDetails({ data }: { data: EntryPayload }) {
  const [revealed, setRevealed] = useState(false)
  const summary = entrySummary(data)
  return <div className="mt-3 space-y-3 rounded-xl border border-white/10 bg-black/20 p-4 text-sm text-slate-300">
    {data.schema_version === 1 && <>
      {data.username && <p className="break-all">{data.username}</p>}
      {data.website && <p className="break-all">{data.website}</p>}
      <p className="break-all" aria-label="Password">{revealed ? data.password : '••••••••'}</p>
      <button type="button" onClick={() => setRevealed(!revealed)} className="text-blue-300 underline">{revealed ? 'Hide password' : 'Show password'}</button>
    </>}
    {data.schema_version === 2 && data.kind === 'card' && <>
      {data.cardholder && <p>{data.cardholder}</p>}
      <p className="break-all" aria-label="Card number">{revealed ? data.card_number : summary.secondary}</p>
      {data.expiry && <p>{data.expiry}</p>}
      <button type="button" onClick={() => setRevealed(!revealed)} className="text-blue-300 underline">{revealed ? 'Hide card number' : 'Show card number'}</button>
    </>}
    {data.notes && <p className="whitespace-pre-wrap break-words">{data.notes}</p>}
  </div>
}

export default function OfflineBackupPanel() {
  const [file, setFile] = useState<File | null>(null)
  const [password, setPassword] = useState('')
  const [backup, setBackup] = useState<BackupContent | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const [cached, setCached] = useState(false)
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const [selected, setSelected] = useState<string | null>(null)
  const operation = useRef<AbortController | null>(null)
  const lastActivity = useRef<number | null>(null)

  const lock = useCallback(() => {
    operation.current?.abort()
    operation.current = null
    lastActivity.current = null
    setBackup(null)
    setPassword('')
    setError('')
    setBusy(false)
    setQuery('')
    setPage(0)
    setSelected(null)
  }, [])

  useEffect(() => {
    const serviceWorker = navigator.serviceWorker
    const checkCache = () => setCached(serviceWorker?.controller?.scriptURL === new URL('/offline-shell.js', location.href).href)
    const expire = () => {
      if (lastActivity.current !== null && Date.now() - lastActivity.current >= IDLE_LIMIT_MS) lock()
    }
    const activity = () => {
      expire()
      if (lastActivity.current !== null) lastActivity.current = Date.now()
    }
    const visibility = () => {
      if (document.hidden) lock()
      else expire()
    }
    checkCache()
    serviceWorker?.addEventListener('controllerchange', checkCache)
    document.addEventListener('visibilitychange', visibility)
    window.addEventListener('pagehide', lock)
    window.addEventListener('pointerdown', activity)
    window.addEventListener('keydown', activity)
    const timer = window.setInterval(expire, 1000)
    return () => {
      operation.current?.abort()
      serviceWorker?.removeEventListener('controllerchange', checkCache)
      document.removeEventListener('visibilitychange', visibility)
      window.removeEventListener('pagehide', lock)
      window.removeEventListener('pointerdown', activity)
      window.removeEventListener('keydown', activity)
      window.clearInterval(timer)
    }
  }, [lock])

  async function open(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (operation.current || !file) return
    const phrase = password
    setPassword('')
    setError('')
    if (file.size > MAX_BACKUP_FILE_BYTES) { setError('Backup file exceeds the 48 MiB limit.'); return }
    const controller = new AbortController()
    operation.current = controller
    setBusy(true)
    try {
      const text = await file.text()
      controller.signal.throwIfAborted()
      const opened = await openBackup(text, phrase, deriveInWorker, controller.signal)
      controller.signal.throwIfAborted()
      lastActivity.current = Date.now()
      setBackup(opened.content)
    } catch (reason) {
      if (!controller.signal.aborted) setError(reason instanceof BackupError ? reason.message : 'Could not open this backup.')
    } finally {
      if (operation.current === controller) {
        operation.current = null
        setBusy(false)
      }
    }
  }

  const input = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none focus:border-blue-400'
  const search = query.trim().toLowerCase()
  const entries = backup?.entries.filter(({ payload }) =>
    [payload.title, payload.category, ENTRY_LABELS[entryKind(payload)]].some((value) => value.toLowerCase().includes(search))) ?? []
  const pages = Math.max(1, Math.ceil(entries.length / PAGE_SIZE))
  const currentPage = Math.min(page, pages - 1)

  return <section aria-labelledby="offline-backup-heading" className="mt-9 max-w-3xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 id="offline-backup-heading" className="text-lg font-semibold">Open an encrypted backup offline</h2>
    <p className="mt-3 text-sm leading-7 text-slate-400">Open a downloaded SafeVault backup with its backup password. This view shows the entries from the time of export.</p>
    <p className="mt-2 text-xs leading-6 text-slate-400">{cached ? 'This browser has saved the app for offline use.' : 'Keep this tab open, or load the production app online to prepare it for offline use.'}</p>
    {error && <p role="alert" className="mt-4 text-sm text-red-300">{error}</p>}
    {backup ? <>
      <div className="mt-5 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-slate-300">{backup.entries.length} entries · {new Date(backup.exported_at).toLocaleString()}</p>
        <button type="button" onClick={lock} className="rounded-xl border border-blue-400/25 px-4 py-2 text-sm text-blue-200">Lock backup</button>
      </div>
      <label className="mt-4 block text-xs text-slate-300">Search backup
        <input value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); setSelected(null) }} className={input} />
      </label>
      <ul className="mt-4 divide-y divide-white/10">
        {entries.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map(({ original_id: id, payload }) => (
          <li key={id} className="py-3">
            <button type="button" aria-expanded={selected === id} onClick={() => setSelected(selected === id ? null : id)} className="block w-full break-words text-left text-sm text-blue-200">
              {payload.title} <span className="ml-2 text-xs text-slate-400">{ENTRY_LABELS[entryKind(payload)]}</span>
            </button>
            {selected === id && <EntryDetails data={payload} />}
          </li>
        ))}
      </ul>
      {!entries.length && <p className="mt-4 text-sm text-slate-400">{search ? 'No matching entries.' : 'This backup is empty.'}</p>}
      {pages > 1 && <div className="mt-4 flex items-center justify-between text-sm">
        <button disabled={!currentPage} onClick={() => { setPage(currentPage - 1); setSelected(null) }} className="underline disabled:opacity-50">Previous</button>
        <span>Page {currentPage + 1} of {pages}</span>
        <button disabled={currentPage + 1 === pages} onClick={() => { setPage(currentPage + 1); setSelected(null) }} className="underline disabled:opacity-50">Next</button>
      </div>}
    </> : <form onSubmit={(event) => void open(event)} className="mt-5 max-w-md space-y-4">
      <label className="block text-xs text-slate-300">Encrypted backup file
        <input type="file" required accept=".json,application/json" disabled={busy} onChange={(event) => { setFile(event.target.files?.[0] ?? null); setPassword(''); setError('') }} className={input} />
      </label>
      <label className="block text-xs text-slate-300">Backup password
        <input type="password" required maxLength={1024} autoComplete="off" disabled={busy} value={password} onChange={(event) => setPassword(event.target.value)} className={input} />
      </label>
      <button disabled={busy || !file} className="rounded-xl brand-primary px-4 py-2.5 text-sm disabled:opacity-50">{busy ? 'Opening backup…' : 'Open backup'}</button>
      {busy && <button type="button" onClick={lock} className="ml-3 text-sm underline">Cancel</button>}
    </form>}
  </section>
}
