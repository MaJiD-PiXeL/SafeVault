import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { X } from 'lucide-react'
import type { VaultController } from './controller'
import type { EntryPayload, UnlockedEntry } from './format'
import { generatePassword } from './generator'
import { passwordWarnings, WARNING_LABELS } from './health'

export default function EntryDialog({ controller, entry, onClose }: {
  controller: VaultController; entry: UnlockedEntry | null; onClose: () => void
}) {
  const state = controller.getSnapshot()
  const dialog = useRef<HTMLDialogElement>(null)
  const [data, setData] = useState<EntryPayload>(() => entry?.data ?? { schema_version: 1, title: '', username: '',
    password: '', website: '', notes: '', category: '', favorite: false })
  const [visible, setVisible] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const warnings = passwordWarnings(data.password)
  useEffect(() => { dialog.current?.showModal() }, [])

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (!state.busy && await controller.save(data, entry?.envelope.id, entry?.envelope.revision, entry?.envelope.state_version)) onClose()
  }

  async function remove() {
    if (!entry || state.busy) return
    if (!confirmDelete) { setConfirmDelete(true); return }
    if (await controller.remove(entry.envelope.id, entry.envelope.revision, entry.envelope.state_version)) onClose()
  }

  const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 text-sm outline-none focus:border-blue-400'
  return <dialog ref={dialog} onCancel={onClose} onClose={onClose} aria-labelledby="entry-heading" className="m-auto max-h-[90vh] w-[calc(100%_-_2rem)] max-w-xl overflow-y-auto rounded-2xl border border-white/10 bg-vault-surface p-6 text-slate-100 backdrop:bg-black/75">
    <div className="flex items-center justify-between"><h2 id="entry-heading" className="text-lg font-semibold">{entry ? 'Edit password' : 'Add password'}</h2><button type="button" aria-label="Close entry" onClick={onClose} className="p-2 text-slate-400"><X size={18} /></button></div>
    <p className="mt-2 text-xs leading-6 text-slate-400">All entry fields are encrypted on this device before saving.</p>
    {state.error && <p role="alert" className="mt-4 text-sm text-red-300">{state.error}</p>}
    <form onSubmit={(event) => void save(event)} className="mt-5 space-y-4">
      <fieldset disabled={state.busy} className="space-y-4 disabled:opacity-60">
        <label className="block text-xs text-slate-300">Title<input required maxLength={500} value={data.title} onChange={(event) => setData({ ...data, title: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Username / Email<input autoComplete="off" maxLength={2000} value={data.username} onChange={(event) => setData({ ...data, username: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Password<input required type={visible ? 'text' : 'password'} autoComplete="off" maxLength={10000} value={data.password} onChange={(event) => setData({ ...data, password: event.target.value })} className={inputClass} /></label>
        {data.password && <p className="text-xs leading-6 text-slate-400">{warnings.length ? `Review: ${warnings.map((warning) => WARNING_LABELS[warning]).join('; ')}.` : 'No local pattern warning. Use a unique password for each account.'}</p>}
        <div className="flex gap-4 text-xs text-blue-300"><button type="button" onClick={() => setVisible(!visible)}>{visible ? 'Hide password' : 'Show password'}</button><button type="button" onClick={() => setData({ ...data, password: generatePassword() })}>Generate password</button></div>
        <label className="block text-xs text-slate-300">Website <span className="text-slate-500">(optional)</span><input autoComplete="off" maxLength={4000} value={data.website} onChange={(event) => setData({ ...data, website: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Notes <span className="text-slate-500">(optional)</span><textarea rows={3} maxLength={50000} value={data.notes} onChange={(event) => setData({ ...data, notes: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Category<input maxLength={200} value={data.category} onChange={(event) => setData({ ...data, category: event.target.value })} className={inputClass} placeholder="e.g. Personal" /></label>
        <label className="flex items-center gap-3 text-sm text-slate-300"><input type="checkbox" checked={data.favorite} onChange={(event) => setData({ ...data, favorite: event.target.checked })} />Favorite</label>
      </fieldset>
      <div className="flex flex-wrap items-center justify-between gap-3 pt-3">
        {entry && <button type="button" disabled={state.busy} onClick={() => void remove()} className="rounded-xl border border-amber-300/20 px-4 py-3 text-xs text-amber-200 disabled:opacity-50">{confirmDelete ? 'Confirm move to Trash' : 'Move to Trash'}</button>}
        <div className="ml-auto flex gap-3"><button type="button" onClick={onClose} className="rounded-xl border border-white/10 px-4 py-3 text-xs">Cancel</button><button disabled={state.busy} className="rounded-xl brand-primary px-4 py-3 text-xs font-semibold disabled:opacity-50">{state.busy ? 'Encrypting and saving...' : 'Save encrypted entry'}</button></div>
      </div>
      {confirmDelete && <p role="status" className="text-xs leading-6 text-amber-200">The saved entry will move to Trash and can be restored. Unsaved edits are discarded. Cancel closes without moving it.</p>}
    </form>
  </dialog>
}
