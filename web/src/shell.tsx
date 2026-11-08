import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Activity,
  Crosshair,
  FileText,
  Globe,
  History,
  LayoutGrid,
  Layers,
  Lock,
  LogOut,
  Moon,
  Search,
  ShieldCheck,
  Sun,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { api, type Alert, type HostView, type User } from './api'
import { NotificationBell } from './notify'

/** The Switchyard mark: an S of track with two rails switching across it. */
export function Mark({ size = 34 }: { size?: number }) {
  return (
    <svg
      className="mark"
      viewBox="133 183 362 320"
      width={size}
      height={(size * 320) / 362}
      aria-hidden="true"
    >
      <path
        className="mark-track"
        d="M495 207 H216.5 A59.5 59.5 0 0 0 216.5 326 H277 L352 376 H418.5 A51.5 51.5 0 0 1 418.5 479 H133"
        fill="none"
        strokeWidth="48"
        strokeLinejoin="round"
      />
      <path
        className="mark-rail"
        d="M495 251 H343 L302 288 L308 299 H315 L335 319 L355 299 H495 Z"
      />
      <path
        className="mark-rail"
        d="M133 437 H264 L305 400 L299 389 H292 L272 369 L252 389 H133 Z"
      />
    </svg>
  )
}

/** Mark and wordmark, linking home. */
export function Logo() {
  return (
    <a className="logo" href="#/dashboard" aria-label="Switchyard home">
      <Mark />
      <span className="logo-name">Switchyard</span>
    </a>
  )
}

type NavItem = {
  path: string
  label: string
  icon: LucideIcon
  admin?: boolean
  badge?: number
}

export function Sidebar({
  route,
  user,
  pending,
  onSignOut,
}: {
  route: string
  user: User
  pending: number
  onSignOut: () => void
}) {
  const groups: { title: string; items: NavItem[] }[] = [
    {
      title: 'Overview',
      items: [
        { path: '/dashboard', label: 'Dashboard', icon: LayoutGrid },
        { path: '/health', label: 'Health', icon: Activity },
      ],
    },
    {
      title: 'Configuration',
      items: [
        { path: '/hosts', label: 'Hosts', icon: Layers },
        { path: '/access', label: 'Access', icon: Lock },
        { path: '/dns', label: 'DNS', icon: Globe },
        { path: '/certificates', label: 'Certificates', icon: ShieldCheck },
        { path: '/honeypot', label: 'Honeypot', icon: Crosshair },
      ],
    },
    {
      title: 'Operations',
      items: [
        {
          path: '/changes',
          label: 'Review & apply',
          icon: Layers,
          badge: pending,
        },
        { path: '/history', label: 'History', icon: History },
        { path: '/audit', label: 'Audit', icon: FileText, admin: true },
      ],
    },
    {
      title: 'Administration',
      items: [{ path: '/users', label: 'Users', icon: Users, admin: true }],
    },
  ]
  const isAdmin = user.role === 'admin'
  const active = (p: string) =>
    route === p || route.startsWith(p + '/') || route.startsWith(p + '?')

  return (
    <aside className="sidebar">
      <Logo />
      <nav aria-label="Main">
        {groups.map((g) => {
          const items = g.items.filter((i) => !i.admin || isAdmin)
          if (items.length === 0) return null
          return (
            <div className="nav-group" key={g.title}>
              <div className="nav-title">{g.title}</div>
              {items.map((i) => (
                <a
                  key={i.path}
                  href={`#${i.path}`}
                  className={`nav-item${active(i.path) ? ' active' : ''}`}
                  aria-current={active(i.path) ? 'page' : undefined}
                >
                  <i.icon size={19} strokeWidth={1.8} aria-hidden="true" />
                  <span>{i.label}</span>
                  {!!i.badge && (
                    <span
                      className="nav-badge"
                      aria-label={`${i.badge} pending`}
                    >
                      {i.badge}
                    </span>
                  )}
                </a>
              ))}
            </div>
          )
        })}
      </nav>
      <div className="sidebar-foot">
        <a
          className="user-card"
          href="#/account"
          title="Your account and two-factor sign-in"
        >
          <span className="avatar" aria-hidden="true">
            {user.username.slice(0, 1).toUpperCase()}
          </span>
          <span>
            <span className="user-name">{user.username}</span>
            <span className="user-role">
              {
                { admin: 'Administrator', editor: 'Editor', viewer: 'Viewer' }[
                  user.role
                ]
              }
            </span>
          </span>
        </a>
        <ThemeToggle />
        <button className="nav-item" onClick={onSignOut}>
          <LogOut size={19} strokeWidth={1.8} aria-hidden="true" />
          <span>Sign out</span>
        </button>
      </div>
    </aside>
  )
}

/** Light by default; dark only when chosen here (remembered). */
function ThemeToggle() {
  const [dark, setDark] = useState(
    () => document.documentElement.dataset.theme === 'dark',
  )
  function toggle() {
    const next = !dark
    setDark(next)
    if (next) document.documentElement.dataset.theme = 'dark'
    else delete document.documentElement.dataset.theme
    try {
      localStorage.setItem('cpm-theme', next ? 'dark' : 'light')
    } catch {
      // not saved; applies to this visit only
    }
  }
  const Icon = dark ? Sun : Moon
  return (
    <button className="nav-item" onClick={toggle}>
      <Icon size={19} strokeWidth={1.8} aria-hidden="true" />
      <span>{dark ? 'Light mode' : 'Dark mode'}</span>
    </button>
  )
}

const pageNames: Record<string, string> = {
  dashboard: 'Dashboard',
  health: 'Health',
  hosts: 'Hosts',
  access: 'Access',
  dns: 'DNS',
  certificates: 'Certificates',
  honeypot: 'Honeypot',
  changes: 'Review & apply',
  history: 'History',
  audit: 'Audit',
  users: 'Users',
  account: 'Account',
  import: 'Import from NPM',
}

function isIP(s: string): boolean {
  return (
    /^\d{1,3}(\.\d{1,3}){3}$/.test(s) ||
    (s.includes(':') && /^[0-9a-f:.]+$/i.test(s))
  )
}

/** Search hosts by domain, or jump to an IP's traffic. ⌘K / Ctrl+K focuses it. */
function GlobalSearch() {
  const [q, setQ] = useState('')
  const [open, setOpen] = useState(false)
  const [hosts, setHosts] = useState<HostView[] | null>(null)
  const [sel, setSel] = useState(0)
  const input = useRef<HTMLInputElement>(null)

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        input.current?.focus()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const results = useMemo(() => {
    const t = q.trim().toLowerCase()
    if (!t) return []
    const out: { label: string; hint: string; href: string }[] = []
    if (isIP(t))
      out.push({
        label: t,
        hint: 'Traffic from this IP',
        href: `#/dashboard?ip=${encodeURIComponent(t)}`,
      })
    for (const h of hosts ?? []) {
      const d = h.domains.find((x) => x.includes(t))
      if (d)
        out.push({
          label: d,
          hint: h.enabled ? 'Host' : 'Host (disabled)',
          href: `#/hosts/${h.id}`,
        })
      if (out.length >= 8) break
    }
    if (!isIP(t) && t.startsWith('/'))
      out.push({
        label: t,
        hint: 'Requests for this path (live view)',
        href: `#/dashboard`,
      })
    return out
  }, [q, hosts])

  function go(i: number) {
    const r = results[i]
    if (!r) return
    location.hash = r.href
    setQ('')
    setOpen(false)
    input.current?.blur()
  }

  return (
    <div className="gsearch">
      <Search size={17} aria-hidden="true" />
      <input
        ref={input}
        type="search"
        aria-label="Search hosts and IPs"
        placeholder="Search hosts, IPs…"
        value={q}
        onFocus={() => {
          setOpen(true)
          if (!hosts)
            api
              .hosts()
              .then(setHosts)
              .catch(() => setHosts([]))
        }}
        onBlur={() => setTimeout(() => setOpen(false), 150)}
        onChange={(e) => {
          setQ(e.target.value)
          setSel(0)
        }}
        onKeyDown={(e) => {
          if (e.key === 'ArrowDown')
            setSel((s) => Math.min(s + 1, results.length - 1))
          else if (e.key === 'ArrowUp') setSel((s) => Math.max(s - 1, 0))
          else if (e.key === 'Enter') go(sel)
          else if (e.key === 'Escape') input.current?.blur()
        }}
      />
      <kbd>⌘K</kbd>
      {open && q.trim() && (
        <div className="gsearch-results" role="listbox">
          {results.length === 0 ? (
            <div className="gsearch-empty">No hosts match “{q.trim()}”.</div>
          ) : (
            results.map((r, i) => (
              <a
                key={r.href + r.label}
                role="option"
                aria-selected={i === sel}
                className={i === sel ? 'selected' : ''}
                href={r.href}
                onMouseDown={(e) => {
                  e.preventDefault()
                  go(i)
                }}
              >
                <span>{r.label}</span>
                <span className="hint">{r.hint}</span>
              </a>
            ))
          )}
        </div>
      )}
    </div>
  )
}

function CaddyStatus() {
  const [ok, setOk] = useState<boolean | null>(null)
  useEffect(() => {
    const load = () =>
      api
        .status()
        .then((s) => setOk(s.caddy.reachable))
        .catch(() => setOk(null))
    load()
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [])
  if (ok === null) return null
  return (
    <a href="#/health" className={`caddy-status ${ok ? 'up' : 'down'}`}>
      <span className="status-dot" aria-hidden="true" />
      {ok ? 'Caddy online' : 'Caddy unreachable'}
    </a>
  )
}

export function Topbar({
  route,
  alerts,
  username,
}: {
  route: string
  alerts: Alert[] | null
  username: string
}) {
  const section = route.split(/[/?]/)[1] || 'dashboard'
  const name = pageNames[section] ?? 'Dashboard'
  const sub = route.startsWith('/hosts/new')
    ? 'New host'
    : /^\/hosts\/\d+/.test(route)
      ? 'Edit host'
      : null
  return (
    <header className="topbar">
      <div className="crumbs">
        <Mark size={18} />
        <span>Switchyard</span>
        <span className="crumb-sep">/</span>
        {sub ? (
          <>
            <a href={`#/${section}`}>{name}</a>
            <span className="crumb-sep">/</span>
            <strong>{sub}</strong>
          </>
        ) : (
          <strong>{name}</strong>
        )}
      </div>
      <GlobalSearch />
      <NotificationBell key={username} alerts={alerts} username={username} />
      <CaddyStatus />
    </header>
  )
}

/** A page's title row: heading, one line on what it's for, actions. */
export function PageHeader({
  title,
  subtitle,
  actions,
}: {
  title: string
  subtitle?: string
  actions?: ReactNode
}) {
  return (
    <div className="page-header">
      <div>
        <h1>{title}</h1>
        {subtitle && <p>{subtitle}</p>}
      </div>
      {actions && <div className="page-actions">{actions}</div>}
    </div>
  )
}
