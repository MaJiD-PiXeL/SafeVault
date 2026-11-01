import { useEffect, useState } from 'react'
import { generatePassword } from './generator'

export default function GeneratorPanel() {
  const [length, setLength] = useState(20)
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [message, setMessage] = useState('')
  useEffect(() => {
    const clear = () => { if (document.hidden) { setPassword(''); setVisible(false); setMessage('') } }
    document.addEventListener('visibilitychange', clear)
    return () => document.removeEventListener('visibilitychange', clear)
  }, [])
  async function copy() {
    try { await navigator.clipboard.writeText(password); setMessage('Copied. Clipboard contents are not cleared automatically.') }
    catch { setMessage('Clipboard access was unavailable. Reveal and copy manually.') }
  }
  return <section className="mt-9 max-w-2xl rounded-2xl border border-white/10 bg-[#0c0f15] p-6 sm:p-8">
    <h2 className="text-lg font-semibold">Password generator</h2><p className="mt-3 text-sm leading-7 text-slate-400">Generate locally with letters, numbers and symbols. Generated passwords are never sent to the server.</p>
    <label className="mt-6 block text-sm text-slate-300">Length: {length}<input aria-label="Password length" type="range" min={12} max={128} value={length} onChange={(event) => setLength(Number(event.target.value))} className="mt-3 block w-full" /></label>
    <input aria-label="Generated password" readOnly type={visible ? 'text' : 'password'} value={password} className="mt-6 w-full rounded-xl border border-white/10 bg-black/20 p-4 font-mono text-sm" />
    <div className="mt-5 flex flex-wrap gap-3"><button onClick={() => { setPassword(generatePassword(length)); setMessage('') }} className="rounded-xl bg-blue-600 px-4 py-3 text-sm">Generate password</button><button disabled={!password} onClick={() => setVisible(!visible)} className="rounded-xl border border-white/10 px-4 py-3 text-sm disabled:opacity-50">{visible ? 'Hide' : 'Reveal'}</button><button disabled={!password} onClick={() => void copy()} className="rounded-xl border border-white/10 px-4 py-3 text-sm disabled:opacity-50">Copy</button></div>
    {message && <p role="status" className="mt-4 text-xs leading-6 text-slate-400">{message}</p>}
  </section>
}
