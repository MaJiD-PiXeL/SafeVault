import { useState } from 'react'
import { RotateCcw, Search, Trash2 } from 'lucide-react'
import type { VaultController } from './controller'
import { entrySummary } from './format'
import type { EncryptedEntry, UnlockedEntry } from './format'
import AttachmentList from './AttachmentList'

const sameVersion = (a: EncryptedEntry | null, b: EncryptedEntry) =>
  a?.id === b.id && a.revision === b.revision && a.state_version === b.state_version

export default function TrashPanel({ controller, entries }: { controller: VaultController; entries: UnlockedEntry[] }) {
  const state = controller.getSnapshot()
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const [confirmation, setConfirmation] = useState<EncryptedEntry | null>(null)
  const [message, setMessage] = useState('')
  const search = query.trim().toLowerCase()
  const filtered = entries.filter(({ data }) => {
    const { primary, secondary } = entrySummary(data)
    return [data.title, primary, secondary, data.category, data.notes]
      .some((value) => value.toLowerCase().includes(search))
  })
    .sort((a, b) => Date.parse(b.envelope.deleted_at!) - Date.parse(a.envelope.deleted_at!))
  const lastPage = Math.max(0, Math.ceil(filtered.length / 20) - 1)
  const currentPage = Math.min(page, lastPage)

  async function restore(envelope: EncryptedEntry) {
    setMessage('')
    setConfirmation(null)
    if (await controller.restoreEntry(envelope.id, envelope.revision, envelope.state_version)) setMessage('Entry restored to your vault.')
  }

  async function purge(envelope: EncryptedEntry) {
    if (!sameVersion(confirmation, envelope)) { setConfirmation(envelope); setMessage(''); return }
    const confirmed = confirmation!
    setMessage('')
    // Use the version the user reviewed, never a newer version after refresh.
    if (await controller.purge(confirmed.id, confirmed.revision, confirmed.state_version)) {
      setConfirmation(null)
      setMessage('Entry permanently deleted from this vault.')
    }
  }

  return <section aria-labelledby="trash-heading" className="mt-9 rounded-2xl border border-white/10 bg-vault-surface p-5 sm:p-8">
    <div className="flex flex-wrap items-center justify-between gap-4">
      <div className="flex items-center gap-3"><Trash2 size={22} className="text-blue-400" /><h2 id="trash-heading" className="text-lg font-semibold">Encrypted Trash</h2></div>
      <button disabled={state.busy} onClick={() => { setConfirmation(null); setMessage(''); void controller.refresh() }} className="rounded-lg border border-white/15 px-4 py-2 text-xs disabled:opacity-50">Refresh Trash</button>
    </div>
    <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">Deleted entries stay encrypted and can be restored with their original details. Items remain here until you explicitly delete them forever. Trash counts toward the vault storage limit.</p>
    <p className="mt-2 text-xs leading-6 text-slate-400">Trash is excluded from the main search, favorites, password health and new backups. Restore an entry first to include it in a backup.</p>
    {state.error && <p role="alert" className="mt-5 rounded-xl border border-red-400/20 p-4 text-sm text-red-300">{state.error}</p>}
    {message && <p role="status" className="mt-5 rounded-xl border border-blue-400/20 p-4 text-sm text-blue-200">{message}</p>}
    <div className="mt-6 flex flex-wrap items-center justify-between gap-3">
      <label className="flex w-full items-center gap-2 rounded-xl border border-white/10 bg-black/20 px-3 py-3 sm:max-w-sm"><Search size={16} className="shrink-0 text-slate-400" /><input aria-label="Search Trash" placeholder="Search Trash..." value={query} onChange={(event) => { setQuery(event.target.value); setPage(0); setConfirmation(null) }} className="min-w-0 flex-1 bg-transparent text-sm outline-none" /></label>
      <span className="text-xs text-slate-400">{filtered.length} of {entries.length} deleted entries</span>
    </div>
    <div className="mt-4 divide-y divide-white/10">{filtered.slice(currentPage * 20, (currentPage + 1) * 20).map(({ envelope, data }) => {
      const confirming = sameVersion(confirmation, envelope)
      return <article key={envelope.id} className="py-5">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0 flex-1"><h3 className="truncate text-sm font-semibold">{data.title}</h3><p className="mt-1 truncate text-xs text-slate-400">{entrySummary(data).primary}</p><p className="mt-2 text-xs text-slate-400">Moved to Trash {new Date(envelope.deleted_at!).toLocaleString()}</p></div>
          <div className="flex flex-wrap gap-2">
            <button disabled={state.busy} aria-label={`Restore ${data.title}`} onClick={() => void restore(envelope)} className="flex items-center gap-2 rounded-lg border border-blue-400/25 px-3 py-2 text-xs text-blue-200 disabled:opacity-50"><RotateCcw size={14} />Restore</button>
            <button disabled={state.busy} aria-label={`${confirming ? 'Confirm permanent deletion of' : 'Delete forever'} ${data.title}`} onClick={() => void purge(envelope)} className="rounded-lg border border-red-400/25 px-3 py-2 text-xs text-red-300 disabled:opacity-50">{confirming ? 'Confirm permanent deletion' : 'Delete forever'}</button>
            {confirming && <button disabled={state.busy} onClick={() => setConfirmation(null)} className="rounded-lg border border-white/15 px-3 py-2 text-xs disabled:opacity-50">Cancel deletion</button>}
          </div>
        </div>
        {data.attachments && <div className="mt-3 max-w-md"><AttachmentList files={data.attachments} /></div>}
        {confirming && <p role="alert" className="mt-4 text-xs leading-6 text-red-300">This permanently removes the encrypted entry from this vault. You cannot undo it here. Previously downloaded backups may still contain copies.</p>}
      </article>
    })}</div>
    {!filtered.length && <div className="py-10 text-center"><p className="text-sm text-slate-400">{entries.length ? 'No deleted entries match your search.' : 'Trash is empty. Entries you move here can be restored later.'}</p>{query && <button onClick={() => { setQuery(''); setPage(0) }} className="mt-4 rounded-lg border border-white/15 px-4 py-2 text-xs">Clear Trash search</button>}</div>}
    {lastPage > 0 && <div className="mt-5 flex items-center justify-between gap-3 text-xs"><button disabled={currentPage === 0} onClick={() => { setPage(currentPage - 1); setConfirmation(null) }} className="rounded-lg border border-white/10 px-3 py-2 disabled:opacity-40">Previous</button><span>Page {currentPage + 1} of {lastPage + 1}</span><button disabled={currentPage === lastPage} onClick={() => { setPage(currentPage + 1); setConfirmation(null) }} className="rounded-lg border border-white/10 px-3 py-2 disabled:opacity-40">Next</button></div>}
  </section>
}
