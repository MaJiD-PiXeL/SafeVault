import { fromBase64, MAX_ATTACHMENT_BYTES, MAX_ATTACHMENT_COUNT, MAX_ATTACHMENTS_BYTES, toBase64,
  validAttachmentName, VaultDataError } from './format.ts'
import type { Attachment } from './format.ts'

export async function readAttachments(files: readonly File[], existing: readonly Attachment[], signal: AbortSignal): Promise<Attachment[]> {
  signal.throwIfAborted()
  if (existing.length + files.length > MAX_ATTACHMENT_COUNT) throw new VaultDataError('Attach up to 3 files per entry.')
  let size = existing.reduce((total, file) => total + file.size, 0)
  for (const file of files) {
    if (!validAttachmentName(file.name)) throw new VaultDataError('Rename the file before attaching it. Use a name of 1–180 characters without path separators or special filename characters.')
    if (file.size < 1 || file.size > MAX_ATTACHMENT_BYTES) throw new VaultDataError('Each attachment must be nonempty and at most 1 MiB.')
    size += file.size
  }
  if (size > MAX_ATTACHMENTS_BYTES) throw new VaultDataError('Attachments can total up to 2 MiB per entry.')

  const added: Attachment[] = []
  for (const file of files) {
    signal.throwIfAborted()
    const bytes = new Uint8Array(await file.arrayBuffer())
    try {
      signal.throwIfAborted()
      if (bytes.length !== file.size) throw new VaultDataError('The file changed while reading it. Select it again.')
      added.push({ name: file.name, size: bytes.length, content: toBase64(bytes) })
    } finally { bytes.fill(0) }
  }
  return added
}

export function attachmentBlob(file: Attachment): Blob {
  if (!validAttachmentName(file.name) || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > MAX_ATTACHMENT_BYTES) {
    throw new VaultDataError('Invalid attachment.')
  }
  const bytes = fromBase64(file.content, file.size)
  try { return new Blob([bytes], { type: 'application/octet-stream' }) }
  finally { bytes.fill(0) }
}
