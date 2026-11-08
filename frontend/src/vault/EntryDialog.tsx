import { useEffect, useRef, useState } from 'react'
import { X } from 'lucide-react'
import type { VaultController } from './controller'
import { ENTRY_LABELS, entryKind, MAX_ATTACHMENT_COUNT, validCardExpiry, VaultDataError } from './format'
import type { Attachment, EntryKind, EntryPayload, UnlockedEntry } from './format'
import AttachmentList from './AttachmentList'
import { readAttachments } from './attachments'
import { generatePassword } from './generator'
import { passwordWarnings, WARNING_LABELS } from './health'

function emptyEntry(kind: EntryKind): EntryPayload {
  const common = { title: '', notes: '', category: '', favorite: false }
  if (kind === 'note') return { schema_version: 2, kind, ...common }
  if (kind === 'card') return { schema_version: 2, kind, ...common, cardholder: '', card_number: '', expiry: '' }
  return { schema_version: 1, ...common, username: '', password: '', website: '' }
}

export default function EntryDialog({ controller, entry, kind, onClose }: {
  controller: VaultController; entry: UnlockedEntry | null; kind: EntryKind; onClose: () => void
}) {
  const state = controller.getSnapshot()
  const dialog = useRef<HTMLDialogElement>(null)
  const fileRead = useRef<AbortController | null>(null)
  const [data, setData] = useState<EntryPayload>(() => entry?.data ?? emptyEntry(kind))
  const [visible, setVisible] = useState(false)
  const [confirmDelete, setConfirmDelete] = useState(false)
  const [validationError, setValidationError] = useState('')
  const [reading, setReading] = useState(false)
  const type = entryKind(data)
  const warnings = data.schema_version === 1 ? passwordWarnings(data.password) : []
  const latest = entry && state.entries.find((item) => item.envelope.id === entry.envelope.id)
  const changed = Boolean(entry && (!latest || latest.envelope.revision !== entry.envelope.revision ||
    latest.envelope.state_version !== entry.envelope.state_version))
  useEffect(() => {
    dialog.current?.showModal()
    return () => { fileRead.current?.abort(); fileRead.current = null }
  }, [])

  function setAttachments(update: (files: Attachment[]) => Attachment[]) {
    setData((previous) => {
      const files = update(previous.attachments ?? [])
      const next = { ...previous }
      if (files.length) next.attachments = files
      else delete next.attachments
      return next
    })
  }

  async function attach(files: File[]) {
    if (!files.length || fileRead.current || state.busy) return
    const operation = new AbortController()
    fileRead.current = operation
    const lockEpoch = state.lockEpoch
    setReading(true)
    setValidationError('')
    try {
      const added = await readAttachments(files, data.attachments ?? [], operation.signal)
      if (operation.signal.aborted || controller.getSnapshot().lockEpoch !== lockEpoch) return
      setAttachments((current) => [...current, ...added])
    } catch (error) {
      if (!operation.signal.aborted && controller.getSnapshot().lockEpoch === lockEpoch) {
        setValidationError(error instanceof VaultDataError ? error.message : 'The file could not be read.')
      }
    } finally {
      if (fileRead.current === operation) { fileRead.current = null; setReading(false) }
    }
  }

  async function save(asCopy = false) {
    if (state.busy || fileRead.current || (changed && !asCopy)) return
    setValidationError('')
    let payload = data
    if (!data.title.trim()) { setValidationError('Enter a title.'); return }
    if (data.schema_version === 2) {
      if (data.kind === 'note' && !data.notes.trim()) { setValidationError('Enter your note.'); return }
      if (data.kind === 'card') {
        const digits = data.card_number.replace(/[ -]/g, '')
        if (!/^[0-9]{12,19}$/.test(digits)) { setValidationError('Enter a card number with 12 to 19 digits.'); return }
        if (!validCardExpiry(data.expiry)) { setValidationError('Enter an expiry in MM/YYYY format.'); return }
        payload = { ...data, card_number: digits }
      }
    }
    const original = asCopy ? undefined : entry?.envelope
    if (await controller.save(payload, original?.id, original?.revision, original?.state_version)) onClose()
  }

  async function remove() {
    if (!entry || state.busy || fileRead.current || changed) return
    if (!confirmDelete) { setConfirmDelete(true); return }
    if (await controller.remove(entry.envelope.id, entry.envelope.revision, entry.envelope.state_version)) onClose()
  }

  const inputClass = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-3 py-2.5 text-sm outline-none focus:border-blue-400'
  return <dialog ref={dialog} onCancel={onClose} onClose={onClose} aria-labelledby="entry-heading" className="m-auto max-h-[90vh] w-[calc(100%_-_2rem)] max-w-xl overflow-y-auto rounded-2xl border border-white/10 bg-vault-surface p-6 text-slate-100 backdrop:bg-black/75">
    <div className="flex items-center justify-between"><h2 id="entry-heading" className="text-lg font-semibold">{entry ? 'Edit' : 'Add'} {ENTRY_LABELS[type]}</h2><button type="button" aria-label="Close entry" onClick={onClose} className="p-2 text-slate-400"><X size={18} /></button></div>
    <p className="mt-2 text-xs leading-6 text-slate-400">All entry fields are encrypted on this device before saving.</p>
    {(validationError || state.error) && <p role="alert" className="mt-4 text-sm text-red-300">{validationError || state.error}</p>}
    {changed && <p role="status" className="mt-4 text-sm text-amber-200">This entry changed on another device. Save your edits as a new copy or close this editor.</p>}
    <form onSubmit={(event) => { event.preventDefault(); void save() }} className="mt-5 space-y-4">
      <fieldset disabled={state.busy || reading} className="space-y-4 disabled:opacity-60">
        <label className="block text-xs text-slate-300">Title<input required maxLength={500} value={data.title} onChange={(event) => setData({ ...data, title: event.target.value })} className={inputClass} /></label>
        {data.schema_version === 1 && <>
        <label className="block text-xs text-slate-300">Username / Email<input autoComplete="off" maxLength={2000} value={data.username} onChange={(event) => setData({ ...data, username: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Password<input required type={visible ? 'text' : 'password'} autoComplete="off" maxLength={10000} value={data.password} onChange={(event) => setData({ ...data, password: event.target.value })} className={inputClass} /></label>
        {data.password && <p className="text-xs leading-6 text-slate-400">{warnings.length ? `Review: ${warnings.map((warning) => WARNING_LABELS[warning]).join('; ')}.` : 'No local pattern warning. Use a unique password for each account.'}</p>}
        <div className="flex gap-4 text-xs text-blue-300"><button type="button" onClick={() => setVisible(!visible)}>{visible ? 'Hide password' : 'Show password'}</button><button type="button" onClick={() => setData({ ...data, password: generatePassword() })}>Generate password</button></div>
        <label className="block text-xs text-slate-300">Website <span className="text-slate-500">(optional)</span><input autoComplete="off" maxLength={4000} value={data.website} onChange={(event) => setData({ ...data, website: event.target.value })} className={inputClass} /></label>
        </>}
        {data.schema_version === 2 && data.kind === 'card' && <>
          <label className="block text-xs text-slate-300">Cardholder<input autoComplete="off" maxLength={200} value={data.cardholder} onChange={(event) => setData({ ...data, cardholder: event.target.value })} className={inputClass} /></label>
          <label className="block text-xs text-slate-300">Card number<input required type={visible ? 'text' : 'password'} inputMode="numeric" autoComplete="off" maxLength={25} value={data.card_number} onChange={(event) => setData({ ...data, card_number: event.target.value })} className={inputClass} /></label>
          <button type="button" className="text-xs text-blue-300" onClick={() => setVisible(!visible)}>{visible ? 'Hide card number' : 'Show card number'}</button>
          <label className="block text-xs text-slate-300">Expiry <span className="text-slate-500">(optional)</span><input autoComplete="off" placeholder="MM/YYYY" maxLength={7} value={data.expiry} onChange={(event) => setData({ ...data, expiry: event.target.value })} className={inputClass} /></label>
        </>}
        <label className="block text-xs text-slate-300">{type === 'note' ? 'Note' : 'Notes (optional)'}<textarea required={type === 'note'} rows={type === 'note' ? 8 : 3} maxLength={50000} value={data.notes} onChange={(event) => setData({ ...data, notes: event.target.value })} className={inputClass} /></label>
        <label className="block text-xs text-slate-300">Category<input maxLength={200} value={data.category} onChange={(event) => setData({ ...data, category: event.target.value })} className={inputClass} placeholder="e.g. Personal" /></label>
        <label className="flex items-center gap-3 text-sm text-slate-300"><input type="checkbox" checked={data.favorite} onChange={(event) => setData({ ...data, favorite: event.target.checked })} />Favorite</label>
        <div className="space-y-2">
          <label className="block text-xs text-slate-300">Attachments
            <input type="file" multiple disabled={(data.attachments?.length ?? 0) >= MAX_ATTACHMENT_COUNT} onChange={(event) => {
              const files = Array.from(event.currentTarget.files ?? [])
              event.currentTarget.value = ''
              void attach(files)
            }} className={`${inputClass} disabled:opacity-50`} />
          </label>
          <p className="text-xs leading-6 text-slate-400">Up to 3 files, 1 MiB each and 2 MiB total. Files are saved with this entry.</p>
          <AttachmentList files={data.attachments ?? []} onRemove={(index) => {
            setValidationError('')
            setAttachments((files) => files.filter((_, position) => position !== index))
          }} />
        </div>
      </fieldset>
      <div className="flex flex-wrap items-center justify-between gap-3 pt-3">
        {entry && !changed && <button type="button" disabled={state.busy || reading} onClick={() => void remove()} className="rounded-xl border border-amber-300/20 px-4 py-3 text-xs text-amber-200 disabled:opacity-50">{confirmDelete ? 'Confirm move to Trash' : 'Move to Trash'}</button>}
        <div className="ml-auto flex gap-3">
          <button type="button" onClick={onClose} className="rounded-xl border border-white/10 px-4 py-3 text-xs">Cancel</button>
          {changed ? <button type="button" disabled={state.busy || reading} onClick={(event) => {
            if (event.currentTarget.form?.reportValidity()) void save(true)
          }} className="rounded-xl brand-primary px-4 py-3 text-xs font-semibold disabled:opacity-50">Save as new copy</button>
            : <button disabled={state.busy || reading} className="rounded-xl brand-primary px-4 py-3 text-xs font-semibold disabled:opacity-50">{reading ? 'Reading files...' : state.busy ? 'Encrypting and saving...' : 'Save encrypted entry'}</button>}
        </div>
      </div>
      {confirmDelete && <p role="status" className="text-xs leading-6 text-amber-200">The saved entry will move to Trash and can be restored. Unsaved edits are discarded. Cancel closes without moving it.</p>}
    </form>
  </dialog>
}
