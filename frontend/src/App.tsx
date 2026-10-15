import { useState } from 'react'
import {
  Activity,
  ArrowDownRight,
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
  LogOut,
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
} from 'lucide-react'

import './index.css'

const accounts = [
  {
    name: 'GitHub',
    category: 'Developer Tools',
    username: 'majid@example.com',
    domain: 'github.com',
    color: '#f1f5f9',
    icon: 'GH',
    favorite: true,
  },
  {
    name: 'Google',
    category: 'Email & Identity',
    username: 'majid@example.com',
    domain: 'accounts.google.com',
    color: '#60a5fa',
    icon: 'G',
    favorite: true,
  },
  {
    name: 'Instagram',
    category: 'Social Media',
    username: '@velnar',
    domain: 'instagram.com',
    color: '#c084fc',
    icon: 'IG',
    favorite: false,
  },
  {
    name: 'Discord',
    category: 'Communication',
    username: 'velnar_dev',
    domain: 'discord.com',
    color: '#818cf8',
    icon: 'D',
    favorite: false,
  },
]

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'All Passwords', icon: KeyRound, count: '24' },
  { label: 'Favorites', icon: Star },
  { label: 'Secure Notes', icon: FolderLock },
  { label: 'Payment Cards', icon: CreditCard },
]

function App() {
  const [activePage, setActivePage] = useState('Overview')
  const [search, setSearch] = useState('')
  const [showAddDialog, setShowAddDialog] = useState(false)

  const filteredAccounts = accounts.filter((account) => {
    const query = search.toLowerCase()

    return (
      account.name.toLowerCase().includes(query) ||
      account.username.toLowerCase().includes(query) ||
      account.domain.toLowerCase().includes(query)
    )
  })

  return (
    <div className="min-h-screen bg-[#08090c] text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-[250px] flex-col border-r border-white/[0.07] bg-[#0a0c11] lg:flex">
        <div className="flex h-[88px] items-center gap-3 px-7">
          <div className="flex h-10 w-10 items-center justify-center overflow-hidden rounded-xl border border-blue-400/20 bg-[#101a30]">
            <img
              src="/velnar_logo.png"
              alt="VELNAR"
              className="h-full w-full object-contain"
            />
          </div>

          <div>
            <div className="text-[15px] font-bold tracking-[0.22em]">
              VELNAR
            </div>
            <div className="mt-1 text-[9px] tracking-[0.25em] text-slate-500">
              SECURE ECOSYSTEM
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
                      {item.count}
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
              <span className="text-[9px] text-slate-500">Ready</span>
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
              V
            </div>

            <div className="min-w-0 flex-1">
              <div className="text-[11px] font-medium">VELNAR User</div>
              <div className="mt-1 text-[10px] text-slate-600">
                Personal Vault
              </div>
            </div>

            <LogOut size={15} className="text-slate-600" />
          </div>
        </div>
      </aside>

      <main className="min-h-screen lg:ml-[250px]">
        <header className="sticky top-0 z-10 flex h-[76px] items-center justify-between border-b border-white/[0.06] bg-[#08090c]/90 px-5 backdrop-blur-xl sm:px-8 xl:px-11">
          <div className="flex items-center gap-2 text-[11px] text-slate-600">
            <span>VELNAR</span>
            <span>/</span>
            <span className="text-slate-300">{activePage}</span>
          </div>

          <div className="flex items-center gap-3">
            <div className="hidden items-center gap-2 rounded-lg border border-white/[0.08] bg-white/[0.025] px-3 py-2 sm:flex">
              <Command size={13} className="text-slate-500" />
              <span className="text-[10px] text-slate-500">
                Personal Workspace
              </span>
              <ChevronDown size={13} className="text-slate-600" />
            </div>

            <button
              aria-label="Help"
              className="flex h-9 w-9 items-center justify-center rounded-xl border border-white/[0.08] text-slate-500 hover:text-white"
            >
              <CircleHelp size={16} />
            </button>

            <div className="flex h-9 w-9 items-center justify-center rounded-xl border border-blue-400/20 bg-blue-500/10 text-blue-300">
              <Fingerprint size={17} />
            </div>
          </div>
        </header>

        <div className="mx-auto max-w-[1500px] px-5 py-8 sm:px-8 xl:px-11 xl:py-10">
          <div className="flex flex-col justify-between gap-5 sm:flex-row sm:items-end">
            <div>
              <div className="mb-3 flex items-center gap-2 text-[10px] uppercase tracking-[0.22em] text-blue-400">
                <span className="h-1.5 w-1.5 rounded-full bg-blue-400" />
                Secure Workspace
              </div>

              <h1 className="text-3xl font-semibold tracking-tight text-white sm:text-[36px]">
                Your digital vault.
              </h1>

              <p className="mt-3 text-[12px] text-slate-500 sm:text-[13px]">
                Everything you need to protect your digital identity.
              </p>
            </div>

            <button
              onClick={() => setShowAddDialog(true)}
              className="flex h-11 items-center justify-center gap-2 rounded-xl bg-blue-600 px-5 text-[12px] font-medium text-white shadow-lg shadow-blue-950/30 transition hover:bg-blue-500"
            >
              <Plus size={16} />
              Add New Item
            </button>
          </div>

          <div className="mt-9 grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatCard
              icon={<Vault size={17} />}
              label="Total Items"
              value="24"
              detail="Stored vault items"
              trend={<ArrowUpRight size={14} />}
            />

            <StatCard
              icon={<ShieldCheck size={17} />}
              label="Security Score"
              value="92"
              suffix="/100"
              detail="Security overview"
              trend={<Activity size={14} />}
            />

            <StatCard
              icon={<Star size={17} />}
              label="Favorites"
              value="08"
              detail="Quick access items"
              trend={<ArrowUpRight size={14} />}
            />

            <StatCard
              icon={<LockKeyhole size={17} />}
              label="Vault Status"
              value="Locked"
              detail="Demo interface only"
              trend={<ShieldCheck size={14} />}
            />
          </div>

          <section className="mt-9 grid grid-cols-1 gap-5 xl:grid-cols-[1fr_320px]">
            <div className="overflow-hidden rounded-2xl border border-white/[0.07] bg-[#0c0f15]">
              <div className="flex flex-col gap-4 border-b border-white/[0.06] p-5 sm:flex-row sm:items-center sm:justify-between sm:px-6">
                <div>
                  <h2 className="text-[14px] font-semibold text-slate-100">
                    Recent Items
                  </h2>
                  <p className="mt-1.5 text-[10px] text-slate-600">
                    Your most recently accessed accounts
                  </p>
                </div>

                <div className="flex gap-2">
                  <div className="flex h-9 min-w-0 flex-1 items-center gap-2 rounded-lg border border-white/[0.07] bg-black/20 px-3 sm:w-52">
                    <Search size={14} className="shrink-0 text-slate-600" />

                    <input
                      value={search}
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
                    key={account.name}
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
                      aria-label={`More options for ${account.name}`}
                      className="hidden h-8 w-8 items-center justify-center rounded-lg text-slate-600 hover:bg-white/[0.05] hover:text-white sm:flex"
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
                  <span>{filteredAccounts.length} demo items displayed</span>
                  <span className="flex items-center gap-1.5">
                    <LockKeyhole size={11} />
                    Interface preview
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
                  onClick={() => setShowAddDialog(true)}
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
                    Real vault data will be connected after security integration.
                  </div>
                </div>
              </div>
            </div>
          </section>

          <footer className="mt-10 flex flex-col gap-2 border-t border-white/[0.05] py-6 text-[10px] text-slate-600 sm:flex-row sm:items-center sm:justify-between">
            <span>
              © 2026 VELNAR. SAFEVAULT INTERFACE PREVIEW.
            </span>
            <span className="flex items-center gap-2">
              <LockKeyhole size={12} />
              Security integration pending
            </span>
          </footer>
        </div>
      </main>

      {showAddDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 p-4 backdrop-blur-sm">
          <div
            role="dialog"
            aria-modal="true"
            aria-labelledby="add-item-title"
            className="w-full max-w-md rounded-2xl border border-white/10 bg-[#0c0f15] p-6 shadow-2xl shadow-black/50"
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
                  This form is a visual prototype.
                </p>
              </div>

              <button
                aria-label="Close dialog"
                onClick={() => setShowAddDialog(false)}
                className="rounded-lg p-2 text-slate-500 hover:bg-white/5 hover:text-white"
              >
                <MoreHorizontal size={18} />
              </button>
            </div>

            <div className="mt-6 space-y-4">
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
            </div>

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
          </div>
        </div>
      )}
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