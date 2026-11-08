import { useEffect, useRef, useState } from 'react'
import { Download, Paperclip, X } from 'lucide-react'
import { attachmentBlob } from './attachments'
import type { Attachment } from './format'

export default function AttachmentList({ files, onRemove }: { files: readonly Attachment[]; onRemove?: (index: number) => void }) {
  const [error, setError] = useState('')
  const pending = useRef(new Map<string, number>())
  useEffect(() => {
    const urls = pending.current
    return () => {
      for (const [url, timer] of urls) { window.clearTimeout(timer); URL.revokeObjectURL(url) }
      urls.clear()
    }
  }, [])

  function download(file: Attachment) {
    setError('')
    try {
      const url = URL.createObjectURL(attachmentBlob(file))
      const timer = window.setTimeout(() => { URL.revokeObjectURL(url); pending.current.delete(url) }, 1000)
      pending.current.set(url, timer)
      const link = document.createElement('a')
      link.href = url
      link.download = file.name
      document.body.append(link)
      try { link.click() } finally { link.remove() }
    } catch { setError('This attachment could not be downloaded.') }
  }

  if (!files.length) return null
  return <>
    {error && <p role="alert" className="text-xs text-red-300">{error}</p>}
    <ul aria-label="Encrypted attachments" className="divide-y divide-white/10 rounded-lg border border-white/10">
      {files.map((file, index) => <li key={`${index}:${file.name}`} className="flex items-center gap-2 px-3 py-2 text-xs text-slate-300">
        <Paperclip size={14} className="shrink-0 text-slate-400" aria-hidden="true" />
        <span className="min-w-0 flex-1 break-all" dir="auto">{file.name}</span>
        <span className="shrink-0 text-slate-400">{file.size < 1024 ? `${file.size} B` : `${Math.ceil(file.size / 1024)} KiB`}</span>
        <button type="button" aria-label={`Download ${file.name}`} onClick={() => download(file)} className="shrink-0 rounded-md p-2 text-blue-300 hover:bg-white/10"><Download size={15} aria-hidden="true" /></button>
        {onRemove && <button type="button" aria-label={`Remove ${file.name}`} onClick={() => onRemove(index)} className="shrink-0 rounded-md p-2 text-slate-400 hover:bg-white/10"><X size={15} aria-hidden="true" /></button>}
      </li>)}
    </ul>
  </>
}
