import { useEffect, useRef, useState } from "react";
import {
  Activity,
  ArrowUpRight,
  ChevronDown,
  CircleHelp,
  Command,
  CreditCard,
  Fingerprint,
  FolderLock,
  Globe,
  KeyRound,
  LayoutDashboard,
  LockKeyhole,
  Plus,
  Search,
  Settings2,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  Star,
  Vault,
  Eye,
  MoreHorizontal,
  X,
} from 'lucide-react'

import './index.css'
import { BRAND } from './brand'
import { checkHealth } from './api'
import AccountPanel from './AccountPanel'
import { useAccount } from './useAccount'
import { useVault } from './vault/useVault'
import type { UnlockedEntry } from './vault/format'
import VaultAccess from './vault/VaultAccess'
import EntryDialog from './vault/EntryDialog'
import GeneratorPanel from './vault/GeneratorPanel'
import SecurityPanel from './vault/SecurityPanel'
import BackupPanel from './vault/BackupPanel'

const demoAccounts = [
  {
    name: 'GitHub',
    category: 'Developer Tools',
    username: 'demo@example.com',
    domain: 'github.com',
    color: '#f1f5f9',
    icon: 'GH',
    favorite: true,
  },
  {
    name: 'Google',
    category: 'Email & Identity',
    username: 'demo@example.com',
    domain: 'accounts.google.com',
    color: '#60a5fa',
    icon: 'G',
    favorite: true,
  },
  {
    name: 'Instagram',
    category: 'Social Media',
    username: '@example',
    domain: 'instagram.com',
    color: '#c084fc',
    icon: 'IG',
    favorite: false,
  },
  {
    name: 'Discord',
    category: 'Communication',
    username: 'demo_developer',
    domain: 'discord.com',
    color: '#818cf8',
    icon: 'D',
    favorite: false,
  },
]

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'All Passwords', icon: KeyRound, count: String(demoAccounts.length) },
  { label: 'Favorites', icon: Star },
  { label: 'Secure Notes', icon: FolderLock },
  { label: 'Payment Cards', icon: CreditCard },
]

function App() {
  const account = useAccount()
  const vault = useVault(account.user?.id ?? null, account.status === 'ready')
  const [activePage, setActivePage] = useState('Overview')
  const [search, setSearch] = useState('')
  const [showAddDialog, setShowAddDialog] = useState(false)
  const [editingEntry, setEditingEntry] = useState<UnlockedEntry | null>(null)
  const [category, setCategory] = useState('')
  const [apiStatus, setApiStatus] = useState('Checking...')
  const [apiError, setApiError] = useState(false)
  const dialogRef = useRef<HTMLDialogElement>(null)

  useEffect(() => {
    if (showAddDialog && !vault.unlocked) dialogRef.current?.showModal()
    else dialogRef.current?.close()
  }, [showAddDialog, vault.unlocked])

  useEffect(() => vault.controller.subscribe(() => {
    if (!vault.controller.getSnapshot().unlocked) {
      setSearch('')
      setCategory('')
      setEditingEntry(null)
      setShowAddDialog(false)
    }
  }), [vault.controller])

  useEffect(() => {
    let cancelled = false
    const controller = new AbortController()

    async function checkApi() {
      try {
        const status = await checkHealth(controller.signal)

        if (!cancelled) {
          setApiStatus(status)
          setApiError(false)
        }
      } catch {
        if (!cancelled) {
          setApiStatus('Offline')
          setApiError(true)
        }
      }
    }

    void checkApi()
    const interval = window.setInterval(() => void checkApi(), 30000)

    return () => {
      cancelled = true
      controller.abort()
      window.clearInterval(interval)
    }
  }, [])

  const accounts: (typeof demoAccounts[number] & { id: string; record?: UnlockedEntry })[] = account.user
    ? vault.entries.map((entry) => ({ id: entry.envelope.id, record: entry, name: entry.data.title,
      username: entry.data.username, domain: entry.data.website, category: entry.data.category,
      favorite: entry.data.favorite, icon: entry.data.title.slice(0, 2).toUpperCase(), color: '#60a5fa' }))
    : demoAccounts.map((entry) => ({ ...entry, id: entry.name }))

  function addItem() {
    if (account.user && !vault.unlocked) { setActivePage('All Passwords'); return }
    setEditingEntry(null)
    setShowAddDialog(true)
  }

  const filteredAccounts = accounts.filter((account) => {
    const query = search.trim().toLowerCase()

    if (activePage === 'Favorites' && !account.favorite) return false
    if (category && account.category !== category) return false

    return (
      account.name.toLowerCase().includes(query) ||
      account.username.toLowerCase().includes(query) ||
      account.domain.toLowerCase().includes(query) ||
      account.category.toLowerCase().includes(query) ||
      (account.record?.data.notes.toLowerCase().includes(query) ?? false)
    )
  })

  return (
    <div className="min-h-screen bg-[#08090B] text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-[250px] flex-col overflow-y-auto border-r border-white/[0.07] bg-[#0a0c11] lg:flex">
        <div className="flex h-[88px] shrink-0 items-center gap-3 px-7">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center overflow-hidden rounded-xl border border-white/10 bg-white/[0.025] p-1">
            <img
              src={BRAND.mark}
              alt={`${BRAND.name} mark`}
              className="h-full w-full object-contain"
            />
          </div>

          <div>
            <div className="text-[15px] font-bold tracking-[0.22em]">
              {BRAND.name}
            </div>
            <div className="mt-1 text-[9px] tracking-[0.06em] text-slate-400">
              {BRAND.tagline}
            </div>
          </div>
        </div>

        <div className="mx-5 mb-7 border-t border-white/[0.06]" />

        <div className="px-5">
          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-600">
            Workspace
          </div>

          <nav className="space-y-1">
            {navigation.map((item) => {
              const Icon = item.icon
              const active = activePage === item.label

              return (
                <button
                  key={item.label}
                  onClick={() => setActivePage(item.label)}
                  className={`group flex w-full items-center gap-3 rounded-xl px-3 py-3 text-left text-[12px] transition ${
                    active
                      ? 'border border-blue-400/15 bg-blue-500/[0.10] text-blue-300'
                      : 'border border-transparent text-slate-500 hover:bg-white/[0.035] hover:text-slate-200'
                  }`}
                >
                  <Icon size={16} strokeWidth={1.7} />

                  <span className="flex-1">{item.label}</span>

                  {item.count && (
                    <span className="text-[10px] text-slate-600">
                      {account.user ? (vault.unlocked ? String(accounts.length) : '—') : item.count}
                    </span>
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        <div className="mt-8 px-5">
          <div className="mb-3 px-3 text-[10px] font-semibold uppercase tracking-[0.2em] text-slate-600">
            Security
          </div>

          <button
            onClick={() => setActivePage('Security Center')}
            className={`flex w-full items-center gap-3 rounded-xl px-3 py-3 text-[12px] transition ${
              activePage === 'Security Center'
                ? 'bg-blue-500/10 text-blue-300'
                : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-200'
            }`}
          >
            <ShieldCheck size={16} strokeWidth={1.7} />
            Security Center
          </button>

          <button
            onClick={() => setActivePage('Password Generator')}
            className={`mt-1 flex w-full items-center gap-3 rounded-xl px-3 py-3 text-[12px] transition ${
              activePage === 'Password Generator'
                ? 'bg-blue-500/10 text-blue-300'
                : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-200'
            }`}
          >
            <Sparkles size={16} strokeWidth={1.7} />
            Password Generator
          </button>
          <button onClick={() => setActivePage('Backups')} className={`mt-1 flex w-full items-center gap-3 rounded-xl px-3 py-3 text-[12px] transition ${activePage === 'Backups' ? 'bg-blue-500/10 text-blue-300' : 'text-slate-500 hover:bg-white/[0.035] hover:text-slate-200'}`}><FolderLock size={16} />Backups</button>
        </div>

        <div className="mt-auto p-5">
          <div className="rounded-2xl border border-blue-400/10 bg-gradient-to-br from-blue-500/[0.09] to-transparent p-4">
            <div className="flex items-center gap-2 text-[11px] font-medium text-blue-200">
              <ShieldEllipsis size={16} />
              Vault Protection
            </div>

            <p className="mt-2 text-[10px] leading-5 text-slate-500">
              Your security starts with the protection of your master key.
            </p>

            <div className="mt-4 flex items-center gap-2">
              <div className="h-1 flex-1 overflow-hidden rounded-full bg-white/10">
                <div className="h-full w-4/5 rounded-full bg-blue-500" />
              </div>
              <span className="text-[9px] text-slate-500">{account.user ? (vault.unlocked ? 'Unlocked' : 'Locked') : 'Preview'}</span>
            </div>
          </div>

          <button
            onClick={() => setActivePage('Settings')}
            className="mt-4 flex w-full items-center gap-3 rounded-xl px-3 py-3 text-[12px] text-slate-500 hover:bg-white/[0.035] hover:text-white"
          >
            <Settings2 size={16} />
            Settings
          </button>

          <div className="mt-4 flex items-center gap-3 border-t border-white/[0.06] pt-5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04] text-[11px] font-semibold text-blue-300">
              N
            </div>

            <div className="min-w-0 flex-1">
              <div className="truncate text-[11px] font-medium">{account.user?.username ?? 'Guest preview'}</div>
              <div className="mt-1 text-[10px] text-slate-600">
                Personal Vault
              </div>
            </div>

            <button aria-label="Account settings" onClick={() => setActivePage('Account')} className="rounded-lg p-2 text-slate-400 hover:bg-white/5"><Settings2 size={15} /></button>
          </div>
        </div>
      </aside>

      <main className="min-h-screen lg:ml-[250px]">
        <header className="sticky top-0 z-10 flex h-[76px] items-center justify-between border-b border-white/[0.06] bg-[#08090B]/90 px-5 backdrop-blur-xl sm:px-8 xl:px-11">
          <div className="flex min-w-0 items-center gap-1 text-[11px] text-slate-600 sm:gap-2">
            <span className="shrink-0">{BRAND.name}</span>
            <span className="shrink-0">/</span>
            <span className="truncate text-slate-300">{activePage}</span>
          </div>

          <div className="flex shrink-0 items-center gap-2 sm:gap-3">
            <button onClick={() => setActivePage('Account')} className="max-w-24 truncate rounded-lg border border-blue-400/20 px-3 py-2 text-xs text-blue-300 sm:max-w-32">{account.user?.username ?? 'Sign in'}</button>
            <div
                role="status"
                aria-live="polite"
                title="Connection to the local Django API"
                className={`hidden items-center gap-2 rounded-full border px-3 py-2 text-[10px] sm:flex ${
                  apiError
                    ? 'border-red-500/25 bg-red-500/[0.07] text-red-300'
                    : apiStatus === 'Checking...'
                      ? 'border-white/[0.08] bg-white/[0.025] text-slate-400'
                      : 'border-blue-400/20 bg-blue-500/[0.07] text-blue-300'
                }`}
              >
                <span
                  className={`h-1.5 w-1.5 rounded-full ${
                    apiError
                      ? 'bg-red-400'
                      : apiStatus === 'Checking...'
                        ? 'bg-slate-400'
                        : 'bg-blue-400'
                  }`}
                />
                Backend: {apiStatus}
              </div>

              <div className="hidden items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 py-2 sm:flex">
              <Command size={13} className="text-slate-500" />
              <span className="text-[10px] text-slate-500">
                Personal Workspace
              </span>
              <ChevronDown size={13} className="text-slate-600" />
            </div>

            <button
              aria-label="Help"
              onClick={() => setActivePage('Help')}
              className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/[0.08] text-slate-500 hover:text-white"
            >
              <CircleHelp size={16} />
            </button>

            <div className="hidden h-9 w-9 items-center justify-center rounded-xl border border-blue-400/20 bg-blue-500/10 text-blue-300 sm:flex">
              <Fingerprint size={17} />
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-[1500px] px-5 py-8 sm:px-8 xl:px-11 xl:py-10">
          <label className="mb-6 block text-sm text-slate-400 lg:hidden">
            Navigate
            <select value={activePage} onChange={(event) => setActivePage(event.target.value)} className="ml-3 rounded-lg border border-white/10 bg-[#0c0f15] p-2">
              {[...navigation.map((item) => item.label), 'Security Center', 'Password Generator', 'Backups', 'Account', 'Settings', 'Help'].map((page) => <option key={page}>{page}</option>)}
            </select>
          </label>
          <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
            <div>
              <div className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.22em] text-blue-400">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                Secure Workspace
              </div>

              <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-[36px]">
                {activePage === 'Overview' ? 'Your digital vault.' : activePage}
              </h1>

              <p className="mt-3 text-[12px] text-slate-500 sm:text-[13px]">
                Everything you need to protect your digital identity.
              </p>
            </div>

            <button
              onClick={addItem}
              className="flex h-11 items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 text-[12px] font-medium text-white shadow-lg shadow-blue-950/30 transition hover:bg-blue-500"
            >
              <Plus size={16} />
              Add New Item
            </button>
          </div>

          {['Overview', 'All Passwords', 'Favorites'].includes(activePage) ? (account.user && !vault.unlocked ?
            <VaultAccess key={`${account.user.id}:${vault.lockEpoch}`} controller={vault.controller} /> : <>
          {account.user && <div className="mt-7 rounded-xl border border-blue-400/15 bg-blue-500/5 p-4">
            <div className="flex flex-wrap items-center justify-between gap-3"><span className="text-xs text-blue-200">Vault unlocked on this device</span><div className="flex gap-3"><button disabled={vault.busy} onClick={() => void vault.controller.refresh()} className="text-xs text-slate-300 disabled:opacity-50">Refresh entries</button><button onClick={vault.controller.lock} className="rounded-lg border border-blue-400/25 px-3 py-2 text-xs text-blue-200">Lock vault</button></div></div>
            {vault.error && <p role="alert" className="mt-3 text-sm text-red-300">{vault.error}</p>}
            <p className="mt-3 text-[11px] text-amber-200/70">Independent security audit pending. Use test credentials.</p>
          </div>}
          <div className="mt-9 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={<Vault size={17} />}
              label="Total Items"
              value={String(accounts.length)}
              detail={account.user ? 'Encrypted entries' : 'Demo items'}
              trend={<ArrowUpRight size={14} />}
            />

            <StatCard
              icon={<ShieldCheck size={17} />}
              label="Security Score"
              value="—"
              detail="Security engine not connected"
              trend={<Activity size={14} />}
            />

            <StatCard
              icon={<Star size={17} />}
              label="Favorites"
              value={String(accounts.filter((account) => account.favorite).length)}
              detail="Quick access items"
              trend={<ArrowUpRight size={14} />}
            />

            <StatCard
              icon={<LockKeyhole size={17} />}
              label="Vault Status"
              value={vault.unlocked ? 'Unlocked' : 'Preview'}
              detail={vault.unlocked ? 'Client-side encryption active' : 'Demo interface only'}
              trend={<ShieldCheck size={14} />}
            />
          </div>

          <section className="mt-9 grid grid-cols-1 gap-5 xl:grid-cols-[1fr_320px]">
            <div className="overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0c0f15]">
              <div className="flex flex-col gap-4 border-b border-white/[0.06] p-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
                <div>
                  <h2 className="text-[14px] font-semibold text-slate-100">
                    {activePage === 'Overview' ? 'Recent Items' : activePage}
                  </h2>
                  <p className="mt-1.5 text-[10px] text-slate-600">
                    {account.user ? 'Your most recently updated entries' : 'Sample accounts'}
                  </p>
                </div>

                <div className="flex gap-2">
                  <select aria-label="Filter category" value={category} onChange={(event) => setCategory(event.target.value)} className="min-w-0 max-w-32 rounded-lg border border-white/10 bg-[#0c0f15] px-2 text-[11px] text-slate-300"><option value="">All categories</option>{[...new Set(accounts.map((item) => item.category).filter(Boolean))].sort().map((value) => <option key={value} value={value}>{value}</option>)}</select>
                  <div className="flex h-9 min-w-0 flex-1 items-center gap-2 rounded-lg border border-white/[0.07] bg-black/20 px-3 sm:w-52">
                    <Search size={14} className="shrink-0 text-slate-600" />

                    <input
                      value={search}
                      aria-label="Search items"
                      onChange={(event) => setSearch(event.target.value)}
                      placeholder="Search items..."
                      className="w-full min-w-0 bg-transparent text-[11px] text-slate-200 outline-none placeholder:text-slate-600"
                    />
                  </div>

                  <button
                    onClick={() => setActivePage('All Passwords')}
                    className="rounded-lg border border-white/[0.07] px-3 text-[10px] text-slate-400 transition hover:bg-white/[0.04]"
                  >
                    View all
                  </button>
                </div>
              </div>

              <div className="hidden grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1fr)_35px] gap-4 border-b border-white/[0.05] px-6 py-3 text-[9px] uppercase tracking-[0.13em] text-slate-600 sm:grid">
                <span>Item</span>
                <span>Username</span>
                <span>Website</span>
                <span />
              </div>

              <div className="divide-y divide-white/[0.045]">
                {filteredAccounts.map((account) => (
                  <div
                    key={account.id}
                    className="grid grid-cols-1 gap-3 px-5 py-4 transition hover:bg-white/[0.018] sm:grid-cols-[minmax(0,1.1fr)_minmax(0,1.2fr)_minmax(0,1fr)_35px] sm:items-center sm:gap-4 sm:px-6"
                  >
                    <div className="flex min-w-0 items-center gap-3">
                      <div
                        className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-white/[0.07] bg-white/[0.035] text-[11px] font-semibold"
                        style={{ color: account.color }}
                      >
                        {account.icon}
                      </div>

                      <div className="min-w-0">
                        <div className="flex items-center gap-2 text-[12px] font-medium text-slate-200">
                          <span className="truncate">{account.name}</span>
                          {account.favorite && (
                            <Star
                              size={11}
                              className="shrink-0 fill-blue-400 text-blue-400"
                            />
                          )}
                        </div>
                        <div className="mt-1 truncate text-[10px] text-slate-600">
                          {account.category}
                        </div>
                      </div>
                    </div>

                    <div className="min-w-0">
                      <div className="text-[9px] text-slate-600 sm:hidden">
                        USERNAME
                      </div>
                      <div className="mt-1 truncate text-[11px] text-slate-400 sm:mt-0">
                        {account.username}
                      </div>
                    </div>

                    <div className="flex min-w-0 items-center gap-2">
                      <Globe
                        size={13}
                        className="hidden shrink-0 text-slate-600 sm:block"
                      />
                      <div className="min-w-0">
                        <div className="text-[9px] text-slate-600 sm:hidden">
                          WEBSITE
                        </div>
                        <div className="mt-1 truncate text-[11px] text-slate-500 sm:mt-0">
                          {account.domain}
                        </div>
                      </div>
                    </div>

                    <button
                      aria-label={`Edit ${account.name}`}
                      disabled={!account.record || vault.busy}
                      onClick={() => { if (account.record) { setEditingEntry(account.record); setShowAddDialog(true) } }}
                      title={account.record ? 'Open encrypted entry' : 'Preview item'}
                      className="flex h-8 w-8 items-center justify-center rounded-lg text-slate-400 hover:bg-white/5 disabled:cursor-not-allowed disabled:opacity-50"
                    >
                      <MoreHorizontal size={16} />
                    </button>
                  </div>
                ))}

                {filteredAccounts.length === 0 && (
                  <div className="px-6 py-12 text-center text-[12px] text-slate-500">
                    No matching items found.
                  </div>
                )}
              </div>

              <div className="border-t border-white/[0.05] px-6 py-4">
                <div className="flex items-center justify-between text-[10px] text-slate-600">
                  <span>{filteredAccounts.length} {account.user ? 'entries' : 'demo items'} displayed</span>
                  <span className="flex items-center gap-1.5">
                    <LockKeyhole size={11} />
                    {account.user ? 'Encrypted storage' : 'Interface preview'}
                  </span>
                </div>
              </div>
            </div>

            <div className="space-y-5">
              <div className="relative overflow-hidden rounded-2xl border border-blue-400/15 bg-gradient-to-br from-[#101a31] via-[#0c111d] to-[#0b0d13] p-6">
                <div className="absolute -right-12 -top-12 h-40 w-40 rounded-full bg-blue-500/[0.08] blur-3xl" />

                <div className="relative flex items-center justify-between">
                  <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-blue-400/20 bg-blue-500/10 text-blue-300">
                    <ShieldCheck size={20} />
                  </div>

                  <span className="rounded-full border border-blue-400/15 bg-blue-500/[0.07] px-2.5 py-1 text-[9px] text-blue-300">
                    Preview
                  </span>
                </div>

                <h3 className="relative mt-6 text-[15px] font-semibold">
                  Security overview
                </h3>

                <p className="relative mt-2 text-[11px] leading-6 text-slate-500">
                  Your vault security metrics will appear here once the security
                  engine is connected.
                </p>

                <div className="relative mt-6 flex items-center justify-between border-t border-white/[0.07] pt-4">
                  <span className="text-[10px] text-slate-500">
                    Security engine
                  </span>
                  <span className="flex items-center gap-2 text-[10px] text-amber-300">
                    <span className="h-1.5 w-1.5 rounded-full bg-amber-400" />
                    Not connected
                  </span>
                </div>
              </div>

              <div className="rounded-2xl border border-white/[0.07] bg-[#0c0f15] p-6">
                <div className="flex items-center gap-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/[0.07] bg-white/[0.035] text-slate-300">
                    <Sparkles size={17} />
                  </div>

                  <div>
                    <h3 className="text-[12px] font-semibold">
                      Quick Actions
                    </h3>
                    <p className="mt-1 text-[10px] text-slate-600">
                      Manage your digital identity
                    </p>
                  </div>
                </div>

                <button
                  onClick={addItem}
                  className="mt-5 flex w-full items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-left transition hover:border-blue-400/20 hover:bg-blue-500/[0.04]"
                >
                  <Plus size={15} className="text-blue-400" />
                  <span className="flex-1 text-[11px] text-slate-300">
                    Add new password
                  </span>
                  <ArrowUpRight size={13} className="text-slate-600" />
                </button>

                <button
                  onClick={() => setActivePage('Password Generator')}
                  className="mt-2 flex w-full items-center gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-left transition hover:border-blue-400/20 hover:bg-blue-500/[0.04]"
                >
                  <KeyRound size={15} className="text-blue-400" />
                  <span className="flex-1 text-[11px] text-slate-300">
                    Generate a password
                  </span>
                  <ArrowUpRight size={13} className="text-slate-600" />
                </button>
              </div>

              <div className="flex items-center gap-3 rounded-xl border border-white/[0.06] bg-white/[0.015] p-4">
                <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-white/[0.04] text-slate-400">
                  <Eye size={16} />
                </div>

                <div>
                  <div className="text-[11px] font-medium text-slate-300">
                    Privacy first
                  </div>
                  <div className="mt-1 text-[10px] leading-5 text-slate-600">
                    {account.user ? 'Sensitive fields are encrypted before synchronization.' : 'Sign in to create or unlock your encrypted vault.'}
                  </div>
                </div>
              </div>
            </div>
          </section>
          </>) : ['Account', 'Settings'].includes(activePage) ? (
            <AccountPanel key={account.user?.id ?? 'anonymous'} user={account.user} status={account.status} onUserChange={account.acceptUser} onRefresh={account.refresh} onLock={vault.controller.lock} />
          ) : activePage === 'Backups' ? (
            !account.user ? <section className="mt-9 rounded-2xl border border-white/10 bg-[#0c0f15] p-6"><h2 className="text-lg font-semibold">Encrypted backups</h2><p className="mt-3 text-sm text-slate-400">Sign in and unlock a vault to export or restore an encrypted backup.</p></section> : !vault.unlocked ? <VaultAccess key={`${account.user.id}:${vault.lockEpoch}`} controller={vault.controller} /> : <BackupPanel key={`${account.user.id}:${vault.lockEpoch}`} controller={vault.controller} />
          ) : activePage === 'Password Generator' ? (
            <GeneratorPanel key={`${account.user?.id ?? 'guest'}:${vault.lockEpoch}`} />
          ) : activePage === 'Security Center' ? (
            <SecurityPanel key={`${account.user?.id ?? 'guest'}:${vault.loaded}`} controller={vault.controller} signedIn={Boolean(account.user)} />
          ) : (
            <section className="mt-9 rounded-2xl border border-white/10 bg-[#0c0f15] p-6">
              <h2 className="text-lg font-semibold">{activePage}</h2>
              <p className="mt-3 text-sm leading-7 text-slate-400">
                {activePage === 'Help'
                  ? 'Sign in under Account, then open All Passwords to create or unlock your encrypted vault. Search, categories and favorites are processed locally after unlocking. Guest accounts display sample items. Independent security review is pending.'
                  : activePage === 'Security Center'
                    ? `Backend: ${apiStatus}. Account: ${account.user ? 'signed in' : 'signed out'}. Client vault encryption and security analysis are pending.`
                    : `${activePage} is not available in this interface preview yet.`}
              </p>
            </section>
          )}

          <footer className="mt-10 flex flex-col gap-2 border-t border-white/[0.05] py-6 text-[10px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <span>
              © 2026 {BRAND.fullName}. {account.user ? 'DEVELOPMENT BUILD.' : 'GUEST PREVIEW.'}
            </span>
            <span className="flex items-center gap-2">
              <LockKeyhole size={12} />
              Independent security audit pending
            </span>
          </footer>
        </div>
      </main>

          {vault.unlocked && showAddDialog && <EntryDialog key={editingEntry?.envelope.id ?? 'new'} controller={vault.controller} entry={editingEntry} onClose={() => { setShowAddDialog(false); setEditingEntry(null) }} />}
          {!vault.unlocked && <dialog
            ref={dialogRef}
            onCancel={() => setShowAddDialog(false)}
            onClose={() => setShowAddDialog(false)}
            aria-modal="true"
            aria-labelledby="add-item-title"
            className="m-auto w-[calc(100%_-_2rem)] max-w-md rounded-2xl border border-white/10 bg-[#0c0f15] p-6 text-slate-100 shadow-2xl shadow-black/50 backdrop:bg-black/75 backdrop:backdrop-blur-sm"
          >
            <div className="flex items-center justify-between">
              <div>
                <h2
                  id="add-item-title"
                  className="text-[16px] font-semibold"
                >
                  Add new item
                </h2>
                <p className="mt-2 text-[11px] text-slate-500">
                  This guest preview does not save data. Sign in and set up a vault to save encrypted entries.
                </p>
              </div>

              <button
                aria-label="Close dialog"
                onClick={() => setShowAddDialog(false)}
                className="rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white"
              >
                <X size={18} />
              </button>
            </div>

            <fieldset disabled className="mt-6 space-y-4 opacity-50">
              <label className="block">
                <span className="text-[11px] text-slate-400">Title</span>
                <input
                  placeholder="e.g. GitHub"
                  className="mt-2 h-11 w-full rounded-xl border border-white/[0.09] bg-black/20 px-3 text-[12px] outline-none placeholder:text-slate-700 focus:border-blue-500/50"
                />
              </label>

              <label className="block">
                <span className="text-[11px] text-slate-400">
                  Username / Email
                </span>
                <input
                  placeholder="Enter username or email"
                  className="mt-2 h-11 w-full rounded-xl border border-white/[0.09] bg-black/20 px-3 text-[12px] outline-none placeholder:text-slate-700 focus:border-blue-500/50"
                />
              </label>

              <label className="block">
                <span className="text-[11px] text-slate-400">
                  Password
                </span>
                <input
                  type="password"
                  placeholder="Enter password"
                  className="mt-2 h-11 w-full rounded-xl border border-white/[0.09] bg-black/20 px-3 text-[12px] outline-none placeholder:text-slate-700 focus:border-blue-500/50"
                />
              </label>
            </fieldset>

            <div className="mt-7 flex gap-3">
              <button
                onClick={() => setShowAddDialog(false)}
                className="h-11 flex-1 rounded-xl border border-white/[0.08] text-[11px] text-slate-400 hover:bg-white/[0.04]"
              >
                Cancel
              </button>

              <button
                onClick={() => setShowAddDialog(false)}
                className="h-11 flex-1 rounded-xl bg-blue-600 text-[11px] font-medium text-white hover:bg-blue-500"
              >
                Close Preview
              </button>
            </div>
          </dialog>}
    </div>
  )
}

function StatCard({
  icon,
  label,
  value,
  suffix,
  detail,
  trend,
}: {
  icon: React.ReactNode
  label: string
  value: string
  suffix?: string
  detail: string
  trend: React.ReactNode
}) {
  return (
    <div className="group rounded-2xl border border-white/[0.07] bg-[#0c0f15] p-5 transition duration-200 hover:border-blue-400/20 hover:bg-[#0e121b]">
      <div className="flex items-center justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/[0.07] bg-white/[0.025] text-slate-400 transition group-hover:border-blue-400/20 group-hover:text-blue-300">
          {icon}
        </div>

        <div className="text-slate-600">{trend}</div>
      </div>

      <div className="mt-6 flex items-baseline gap-1">
        <span className="text-[29px] font-semibold tracking-tight text-white">
          {value}
        </span>
        {suffix && (
          <span className="text-[11px] text-slate-600">{suffix}</span>
        )}
      </div>

      <div className="mt-1 text-[11px] text-slate-400">{label}</div>
      <div className="mt-3 text-[10px] text-slate-600">{detail}</div>
    </div>
  )
}

export default App
