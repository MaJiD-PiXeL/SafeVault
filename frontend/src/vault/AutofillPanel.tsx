import { useState } from 'react'
import type { VaultController } from './controller'
import { matchesFill, pairedExtension, pairExtension, sendFill } from './autofill'
import type { FillRequest } from './autofill'

export function ExtensionPairing({ owner }: { owner: number }) {
  const [id, setId] = useState(() => pairedExtension(owner))
  const [message, setMessage] = useState('')
  return <section className="mt-8 border-t border-white/10 pt-6"><h3 className="text-sm font-semibold">Browser autofill</h3>
    <p className="mt-3 text-xs leading-6 text-slate-400">Install the SafeVault extension in Chrome or Edge. Copy its ID from the extension popup and pair it here. Only pair the extension you installed and trust. You approve each fill on an exact matching HTTPS origin.</p>
    <form className="mt-4 space-y-4" onSubmit={event => { event.preventDefault(); try { pairExtension(owner, id); setMessage(id ? 'Extension paired in this browser.' : 'Extension pairing removed.') } catch (reason) { setMessage((reason as Error).message) } }}>
      <label className="block text-xs text-slate-300">Extension ID<input value={id} maxLength={32} autoComplete="off" spellCheck={false} onChange={event => setId(event.target.value)} className="mt-2 block w-full rounded-xl border border-white/10 bg-black/20 px-4 py-3 text-sm" /></label>
      <button className="rounded-xl border border-white/10 px-4 py-2.5 text-sm">Save pairing</button>
    </form>{message && <p role="status" className="mt-3 text-xs text-blue-300">{message}</p>}
  </section>
}

export function AutofillRequestPanel({ request, controller, onClose }: { request: FillRequest; controller: VaultController; onClose: () => void }) {
  const state = controller.getSnapshot()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const matches = state.entries.filter(entry => matchesFill(entry.data, request.origin))
  const paired = state.ownerId !== null && pairedExtension(state.ownerId) === request.extension
  async function fill(id: string) {
    if (busy) return
    controller.checkIdle()
    const current = controller.getSnapshot()
    const entry = current.entries.find(item => item.envelope.id === id)
    if (!current.unlocked || !current.ownerId || !entry) return
    setBusy(true); setError('')
    try { await sendFill(current.ownerId, request, entry.data); onClose() }
    catch (reason) { setError((reason as Error).message) }
    finally { setBusy(false) }
  }
  return <section className="mt-7 rounded-2xl border border-blue-400/30 bg-vault-surface p-6">
    <h2 className="font-semibold">Approve password fill</h2><p className="mt-3 break-all text-sm text-blue-200">{request.origin}</p>
    <p className="mt-2 text-xs leading-6 text-slate-400">This website will receive the selected username and password. Nothing is submitted automatically. Requests expire after two minutes.</p>
    {!paired ? <p className="mt-3 text-sm text-amber-200">Pair your installed extension in Security Center before approving a request.</p> : !state.unlocked ? <p className="mt-3 text-sm">Sign in and unlock your vault to choose a login.</p> : <ul className="mt-4 space-y-3">{matches.map(entry => <li key={entry.envelope.id}><button disabled={busy} onClick={() => void fill(entry.envelope.id)} className="rounded-lg border border-white/15 px-4 py-3 text-sm">Fill {entry.data.title}</button></li>)}</ul>}
    {paired && state.unlocked && !matches.length && <p className="mt-3 text-xs">No password entries match this exact HTTPS origin. Update the entry's website in your vault if needed.</p>}
    {error && <p role="alert" className="mt-3 text-sm text-red-300">{error}</p>}
    <button type="button" disabled={busy} onClick={onClose} className="mt-4 text-xs underline">Dismiss request</button>
  </section>
}
