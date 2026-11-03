import { useEffect, useState } from 'react'
import { DEFAULT_GENERATOR_OPTIONS, generatePassword } from './generator'
import type { GeneratorOptions } from './generator'

export default function GeneratorPanel() {
  const [length, setLength] = useState(20)
  const [password, setPassword] = useState('')
  const [visible, setVisible] = useState(false)
  const [message, setMessage] = useState('')
  const [options, setOptions] = useState<GeneratorOptions>({ ...DEFAULT_GENERATOR_OPTIONS })
  const hasGroup = options.uppercase || options.lowercase || options.digits || options.symbols
  function clear() { setPassword(''); setVisible(false); setMessage('') }
  useEffect(() => {
    const clear = () => { if (document.hidden) { setPassword(''); setVisible(false); setMessage('') } }
    document.addEventListener('visibilitychange', clear)
    return () => document.removeEventListener('visibilitychange', clear)
  }, [])
  async function copy() {
    try { await navigator.clipboard.writeText(password); setMessage('Copied. Clipboard contents are not cleared automatically.') }
    catch { setMessage('Clipboard access was unavailable. Reveal and copy manually.') }
  }
  return <section className="mt-9 max-w-2xl rounded-2xl border border-white/10 bg-vault-surface p-6 sm:p-8">
    <h2 className="text-lg font-semibold">Password generator</h2><p className="mt-3 text-sm leading-7 text-slate-400">Generate locally with your choice of characters. Every selected group is included. Generated passwords are never sent to the server.</p>
    <label className="mt-6 block text-sm text-slate-300">Length: {length}<input aria-label="Password length" type="range" min={12} max={128} value={length} onChange={(event) => { setLength(Number(event.target.value)); clear() }} className="mt-3 block w-full" /></label>
    <fieldset className="mt-6 grid grid-cols-1 gap-4 sm:grid-cols-2"><legend className="mb-3 text-sm text-slate-300">Character options</legend>{([
      ['uppercase', 'Uppercase (A–Z)'], ['lowercase', 'Lowercase (a–z)'], ['digits', 'Numbers (0–9)'], ['symbols', 'Symbols (!@#)'], ['excludeSimilar', 'Exclude similar characters (I, l, 1, O, 0, o)'],
    ] as const).map(([key, label]) => <label key={key} className="flex items-center gap-3 text-xs leading-6 text-slate-300"><input type="checkbox" checked={options[key]} onChange={(event) => { setOptions({ ...options, [key]: event.target.checked }); clear() }} />{label}</label>)}</fieldset>
    {!hasGroup && <p role="alert" className="mt-4 text-sm text-amber-200">Select at least one character group.</p>}
    <input aria-label="Generated password" readOnly type={visible ? 'text' : 'password'} value={password} className="mt-6 w-full rounded-xl border border-white/10 bg-black/20 p-4 font-mono text-sm" />
    <div className="mt-5 flex flex-wrap gap-3"><button disabled={!hasGroup} onClick={() => { setPassword(generatePassword(length, options)); setVisible(false); setMessage('') }} className="rounded-xl brand-primary px-4 py-3 text-sm disabled:opacity-50">Generate password</button><button disabled={!password} onClick={() => setVisible(!visible)} className="rounded-xl border border-white/10 px-4 py-3 text-sm disabled:opacity-50">{visible ? 'Hide' : 'Reveal'}</button><button disabled={!password} onClick={() => void copy()} className="rounded-xl border border-white/10 px-4 py-3 text-sm disabled:opacity-50">Copy</button><button disabled={!password} onClick={clear} className="rounded-xl border border-white/10 px-4 py-3 text-sm disabled:opacity-50">Clear</button></div>
    {message && <p role="status" className="mt-4 text-xs leading-6 text-slate-400">{message}</p>}
  </section>
}
