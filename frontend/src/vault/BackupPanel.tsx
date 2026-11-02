import { useEffect, useRef, useState } from 'react'
import type { FormEvent } from 'react'
import { MAX_BACKUP_FILE_BYTES } from './backup'
import type { VaultController } from './controller'

export default function BackupPanel({ controller }: { controller: VaultController }) {
  const state = controller.getSnapshot()
  const [exportPassword, setExportPassword] = useState('')
  const [confirmation, setConfirmation] = useState('')
  const [importPassword, setImportPassword] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [download, setDownload] = useState<{ url: string; name: string } | null>(null)
  const downloadURL = useRef<string | null>(null)
  const [error, setError] = useState('')
  const [reading, setReading] = useState(false)
  const busy = state.busy || reading
  const mounted = useRef(true)
  const readGeneration = useRef(0)
  useEffect(() => {
    mounted.current = true
    return () => {
      mounted.current = false
      readGeneration.current += 1
      if (downloadURL.current) URL.revokeObjectURL(downloadURL.current)
      controller.cancelBackupWork()
    }
  }, [controller])

  async function prepareExport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    setError('')
    if (exportPassword !== confirmation) { setError('Backup passwords do not match.'); return }
    const password = exportPassword
    setExportPassword('')
    setConfirmation('')
    if (downloadURL.current) URL.revokeObjectURL(downloadURL.current)
    downloadURL.current = null
    setDownload(null)
    if (!await controller.exportBackup(password)) return
    const current = controller.getSnapshot()
    if (!mounted.current || current.lockEpoch !== state.lockEpoch || !current.unlocked || !current.backupExport) return
    const url = URL.createObjectURL(new Blob([current.backupExport.text], { type: 'application/json' }))
    downloadURL.current = url
    setDownload({ url, name: current.backupExport.fileName })
  }

  async function preview(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy || !file) return
    setError('')
    controller.clearBackupPreview()
    const password = importPassword
    setImportPassword('')
    if (file.size > MAX_BACKUP_FILE_BYTES) { setError('Backup file exceeds the 48 MiB limit.'); return }
    const generation = ++readGeneration.current
    setReading(true)
    try {
      const text = await file.text()
      if (!mounted.current || generation !== readGeneration.current || controller.getSnapshot().lockEpoch !== state.lockEpoch || !controller.getSnapshot().unlocked) return
      await controller.prepareRestore(text, password)
    } catch { if (mounted.current) setError('Could not read this backup file.') }
    finally { if (mounted.current && generation === readGeneration.current) setReading(false) }
  }

  const input = 'mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-3 py-3 text-sm outline-none focus:border-blue-400'
  return <section className="mt-9 max-w-3xl space-y-6" aria-labelledby="backup-heading">
    <div><h2 id="backup-heading" className="text-xl font-semibold">Encrypted backups</h2><p className="mt-3 text-sm leading-7 text-slate-400">Backups use their own password and fresh encryption keys. File contents and passwords stay on this device.</p></div>
    {(error || state.error) && <p role="alert" className="rounded-xl border border-red-400/20 bg-red-400/5 p-4 text-sm text-red-300">{error || state.error}</p>}
    {state.backupResult && <p role="status" className="rounded-xl border border-blue-400/20 p-4 text-sm text-blue-200">{state.backupResult}</p>}
    <div className="rounded-2xl border border-white/10 bg-[#0c0f15] p-6">
      <h3 className="font-semibold">Export current vault</h3><p className="mt-2 text-xs leading-6 text-slate-400">The export refreshes and authenticates all entries first. Keep the backup password safe; you need it to restore this file.</p>
      <form onSubmit={(event) => void prepareExport(event)} className="mt-5 max-w-md space-y-4">
        <label className="block text-xs text-slate-300">New backup password<input required type="password" autoComplete="off" minLength={12} maxLength={1024} disabled={state.busy} value={exportPassword} onChange={(event) => setExportPassword(event.target.value)} className={input} /></label>
        <label className="block text-xs text-slate-300">Confirm backup password<input required type="password" autoComplete="off" maxLength={1024} disabled={state.busy} value={confirmation} onChange={(event) => setConfirmation(event.target.value)} className={input} /></label>
        <button disabled={state.busy} className="rounded-xl bg-blue-600 px-4 py-3 text-sm disabled:opacity-50">{state.busy ? 'Working...' : 'Prepare encrypted backup'}</button>
      </form>
      {download && <a href={download.url} download={download.name} className="mt-5 inline-block rounded-xl border border-blue-400/30 px-4 py-3 text-sm text-blue-300">Download encrypted backup</a>}
    </div>
    <div className="rounded-2xl border border-white/10 bg-[#0c0f15] p-6">
      <h3 className="font-semibold">Restore into this vault</h3><p className="mt-2 text-xs leading-6 text-slate-400">Choose a backup and validate it locally. Restoring adds new copies with fresh identities; existing entries are preserved. The same file is restored only once per destination vault.</p>
      <form onSubmit={(event) => void preview(event)} className="mt-5 max-w-md space-y-4">
        <label className="block text-xs text-slate-300">Encrypted backup file<input required type="file" accept=".json,application/json" disabled={busy} onChange={(event) => { readGeneration.current += 1; setFile(event.target.files?.[0] ?? null); setImportPassword(''); setError(''); controller.clearBackupPreview() }} className={input} /></label>
        <label className="block text-xs text-slate-300">Backup password<input required type="password" autoComplete="off" maxLength={1024} disabled={state.busy} value={importPassword} onChange={(event) => setImportPassword(event.target.value)} className={input} /></label>
        <button disabled={busy || !file} className="rounded-xl border border-blue-400/25 px-4 py-3 text-sm text-blue-200 disabled:opacity-50">{busy ? 'Working...' : 'Validate and preview'}</button>
      </form>
      {state.backupPreview && <div className="mt-6 rounded-xl border border-white/10 p-4">
        <h4 className="text-sm font-medium">Validated backup: {state.backupPreview.count} entries</h4>
        <p className="mt-2 text-xs text-slate-400">Snapshot created {new Date(state.backupPreview.exportedAt).toLocaleString('en-US')}</p>
        <ul className="mt-3 space-y-2 text-sm text-slate-300">{state.backupPreview.titles.map((title, index) => <li key={index} className="break-words">{title}</li>)}</ul>
        {state.backupPreview.count > 10 && <p className="mt-3 text-xs text-slate-500">Showing the first 10 entry titles.</p>}
        {state.backupPreview.alreadyRestored ? <p role="status" className="mt-4 text-sm text-blue-200">This backup has already been restored into this vault. No duplicates will be added.</p> : state.backupPreview.count === 0 ? <p className="mt-4 text-sm text-slate-400">This valid backup contains no entries.</p> : <button disabled={state.busy} onClick={() => void controller.restoreBackup()} className="mt-5 rounded-xl bg-blue-600 px-4 py-3 text-sm disabled:opacity-50">{state.busy ? 'Restoring...' : `Restore ${state.backupPreview.count} entries as new copies`}</button>}
      </div>}
    </div>
    <p className="text-xs leading-6 text-amber-200/70">Independent security audit pending. Use test credentials. A backup contains a snapshot, not your account or sessions.</p>
  </section>
}
