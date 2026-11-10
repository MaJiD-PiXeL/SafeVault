import AttachmentList from './AttachmentList'
import type { VaultController } from './controller'
import type { EntryPayload } from './format'
import { pendingWriteId } from './outbox'

const statusText = {
  waiting: 'Waiting to sync.',
  conflict: 'The server version changed. You can keep your draft as a separate entry.',
  blocked: 'The server rejected this draft. Check vault capacity and try syncing again.',
  unavailable: 'This draft cannot be opened with the current vault key.',
}

const trashStatusText = {
  waiting: 'Waiting to sync.',
  conflict: 'The server record changed. Review its current state before requesting this action again.',
  blocked: 'The server rejected this Trash change.',
  unavailable: 'This change requires the previous vault key.',
}

function DraftPreview({ data }: { data: EntryPayload }) {
  const fields = data.schema_version === 1 ? [['Username / Email', data.username], ['Website', data.website]] :
    data.kind === 'card' ? [['Cardholder', data.cardholder], ['Expiry', data.expiry]] : []
  const secret = data.schema_version === 1 ? ['Password', data.password] : data.kind === 'card' ? ['Card number', data.card_number] : null
  return <div className="mt-3 space-y-3 text-xs text-slate-300">
    <dl className="space-y-2">
      {[...fields, ['Category', data.category], ['Notes', data.notes]].filter(([, value]) => value).map(([label, value]) =>
        <div key={label}><dt className="text-slate-400">{label}</dt><dd className="whitespace-pre-wrap break-all" dir="auto">{value}</dd></div>)}
      {data.favorite && <div><dt>Favorite</dt><dd>Yes</dd></div>}
    </dl>
    {secret && <details><summary className="cursor-pointer text-blue-200">Show {secret[0].toLowerCase()}</summary>
      <p className="mt-2 break-all" dir="auto">{secret[1]}</p></details>}
    <AttachmentList files={data.attachments ?? []} />
  </div>
}

export default function PendingChanges({ controller }: { controller: VaultController }) {
  const { pending, pendingError, busy, error } = controller.getSnapshot()
  if (!pending.length && !pendingError) return null
  const buttonClass = 'rounded-lg border border-white/10 px-3 py-2 text-xs disabled:opacity-50'
  return <section aria-labelledby="pending-heading" className="mt-7 space-y-3 rounded-xl border border-amber-300/20 bg-vault-surface p-4">
    <div className="flex flex-wrap items-center justify-between gap-3">
      <h2 id="pending-heading" className="text-sm font-semibold text-amber-100">Local changes ({pending.length})</h2>
      <button type="button" className={buttonClass} disabled={busy} onClick={() => void controller.refresh()}>Sync now</button>
    </div>
    <p className="text-xs text-slate-400">Changes are queued on this device. The vault and Trash show the last confirmed state. Each entry can have one pending change.</p>
    {pendingError && <p role="alert" className="text-xs text-red-300">{pendingError}</p>}
    {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    <ul className="space-y-2">
      {pending.map(({ write, data, status }) => <li key={pendingWriteId(write)} className="space-y-2 rounded-lg border border-white/10 p-3">
        <p dir="auto" className="break-all text-sm text-white">{data?.title ?? 'Encrypted entry'}</p>
        {write.kind && <p className="text-xs text-slate-400">{write.kind === 'move' ? 'Move to Trash' : 'Restore from Trash'}</p>}
        <p className="text-xs text-amber-200">{(write.kind ? trashStatusText : statusText)[status]}</p>
        {!write.kind && data && <details><summary className="cursor-pointer text-xs text-blue-200">Review draft</summary><DraftPreview data={data} /></details>}
        <div className="flex flex-wrap gap-2">
          {!write.kind && status === 'conflict' && <button type="button" className={buttonClass} disabled={busy} onClick={() => {
            void controller.resolvePending(pendingWriteId(write), true).then((saved) => { if (saved) void controller.sync() })
          }}>Save draft as new copy</button>}
          <button type="button" className={buttonClass} disabled={busy} onClick={() => {
            if (window.confirm('Discard this local change? Any change already synced to the server stays applied.')) {
              void controller.resolvePending(pendingWriteId(write), false)
            }
          }}>Discard local change</button>
        </div>
      </li>)}
    </ul>
  </section>
}
