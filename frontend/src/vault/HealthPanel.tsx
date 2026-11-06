import { useMemo, useState } from 'react'
import { ArrowUpRight, ShieldCheck, LockKeyhole } from 'lucide-react'
import type { UnlockedEntry } from './format'
import { analyzePasswords, WARNING_LABELS } from './health'

export default function HealthPanel({ entries, unlocked, busy, onUnlock, onEdit }: {
  entries: UnlockedEntry[]; unlocked: boolean; busy: boolean; onUnlock: () => void; onEdit: (entry: UnlockedEntry) => void
}) {
  const report = useMemo(() => analyzePasswords(unlocked ? entries : []), [entries, unlocked])
  const [filter, setFilter] = useState('review')
  const [page, setPage] = useState(0)
  const byId = new Map(entries.map((entry) => [entry.envelope.id, entry]))
  const findings = report.findings.filter((finding) => filter === 'weak' ? finding.warnings.length > 0 : filter === 'reused' ? finding.reuseCount > 1 : finding.warnings.length > 0 || finding.reuseCount > 1)
  const lastPage = Math.max(0, Math.ceil(findings.length / 20) - 1)
  const currentPage = Math.min(page, lastPage)
  return <section aria-labelledby="health-heading" className="mt-9 rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <div className="flex items-center gap-3"><ShieldCheck className="text-blue-400" size={22} /><h2 id="health-heading" className="text-lg font-semibold">Password health</h2><span className="ml-auto rounded-full border border-white/10 px-3 py-1 text-xs text-slate-400">On this device</span></div>
    <p className="mt-3 max-w-3xl text-sm leading-7 text-slate-400">Find short passwords, common patterns and exact password reuse locally. No passwords or findings are uploaded. These basic checks do not measure cracking time or check data breaches.</p>
    {!unlocked ? <div className="mt-6 rounded-xl border border-white/10 bg-black/20 p-5"><LockKeyhole size={20} className="text-slate-400" /><p className="mt-3 text-sm text-slate-300">Unlock a vault to review its passwords.</p><button onClick={onUnlock} className="brand-primary mt-4 rounded-lg px-4 py-2 text-sm">Open vault</button></div> : <>
      <div className="mt-6 grid grid-cols-2 gap-3 sm:grid-cols-4">{[
        ['Passwords checked', report.total], ['Need review', report.review], ['Weak patterns', report.weak], ['Reused passwords', report.reused],
      ].map(([label, count]) => <div key={label} className="rounded-xl border border-white/10 bg-black/20 p-4"><div className="text-2xl font-semibold">{count}</div><div className="mt-2 text-xs text-slate-400">{label}</div></div>)}</div>
      <p className="mt-4 text-xs leading-6 text-slate-400">Counts refer to entries and can overlap. Reuse comparisons preserve case, spaces and Unicode exactly. A password with no warning can still be predictable or compromised.</p>
      <div className="mt-6 flex flex-wrap items-center justify-between gap-3"><label className="text-sm text-slate-300">Show <select value={filter} onChange={(event) => { setFilter(event.target.value); setPage(0) }} className="ml-2 rounded-lg border border-white/10 bg-vault-raised p-2"><option value="review">All needing review</option><option value="weak">Weak patterns</option><option value="reused">Reused passwords</option></select></label><span role="status" className="text-xs text-slate-400">{findings.length} entries</span></div>
      <div className="mt-4 divide-y divide-white/10">{findings.slice(currentPage * 20, (currentPage + 1) * 20).map((finding) => {
        const entry = byId.get(finding.id)!
        if (entry.data.schema_version !== 1) return null
        return <div key={finding.id} className="flex flex-wrap items-center justify-between gap-4 py-5"><div className="min-w-0 flex-1"><h3 className="truncate text-sm font-semibold">{entry.data.title}</h3><p className="mt-1 truncate text-xs text-slate-400">{entry.data.username}</p><div className="mt-3 flex flex-wrap gap-2">{finding.warnings.map((warning) => <span key={warning} className="rounded-md border border-amber-300/20 bg-amber-300/5 px-2 py-1 text-xs text-amber-200">{WARNING_LABELS[warning]}</span>)}{finding.reuseCount > 1 && <span className="rounded-md border border-blue-400/20 bg-blue-400/5 px-2 py-1 text-xs text-blue-200">Used in {finding.reuseCount} entries</span>}</div></div><button disabled={busy} onClick={() => onEdit(entry)} aria-label={`Review ${entry.data.title}`} className="flex items-center gap-2 rounded-lg border border-white/15 px-4 py-2 text-xs disabled:opacity-50">Review <ArrowUpRight size={14} /></button></div>
      })}</div>
      {!findings.length && <p className="mt-5 rounded-xl border border-white/10 p-5 text-sm text-slate-300">{report.total === 0 ? 'Add your first password to start a local review.' : 'No entries match this check.'}</p>}
      {lastPage > 0 && <div className="mt-5 flex items-center justify-between gap-3 text-xs"><button disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)} className="rounded-lg border border-white/10 px-3 py-2 disabled:opacity-40">Previous</button><span>Page {currentPage + 1} of {lastPage + 1}</span><button disabled={currentPage === lastPage} onClick={() => setPage(currentPage + 1)} className="rounded-lg border border-white/10 px-3 py-2 disabled:opacity-40">Next</button></div>}
      <p className="mt-5 text-xs leading-6 text-slate-400">Use Review to generate and save a unique replacement here. Update the password on the corresponding website as well; saving in this vault does not change that account.</p>
    </>}
  </section>
}
