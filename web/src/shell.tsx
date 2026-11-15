import {
  useEffect,
  useId,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react'
import {
  Activity,
  Crosshair,
  FileText,
  History,
  KeyRound,
  LayoutGrid,
  Layers,
  Lock,
  LogOut,
  Mail,
  Moon,
  Plug,
  Search,
  ShieldCheck,
  Sun,
  Users,
  type LucideIcon,
} from 'lucide-react'
import { api, type Alert, type HostView, type User } from './api'
import { NotificationBell } from './notify'

/**
 * The Hackspacelabs H: warm bands over cool ones, split by a gap that
 * steps up across the crossbar. Drawn on a 700 × 670 grid (the H spans
 * 35–665 × 45–630).
 */
const markH =
  'M95 45H215L255 85V240H445V85L485 45H605L665 105V570L605 630H485L445 590V465H255V590L215 630H95L35 570V105Z'
// The gap between warm and cool, as a centre line.
const markGap =
  'M0 434H168C206 434 206 374 244 374H446C496 374 496 277 546 277H700'
// [colour, lower edge] from the top band down; navy fills the rest.
const markBands: [string, string][] = [
  ['#fbae2c', 'M0 112C150 92 260 138 410 118S610 96 700 100'],
  ['#ffc760', 'M0 176C150 160 260 196 420 170S620 142 700 142'],
  ['#fb7d24', 'M0 272C140 256 260 292 400 276S600 226 700 222'],
  ['#ec2d1d', 'M0 338C150 318 300 352 450 332S620 282 700 277'],
  ['#d81f27', markGap],
  ['#74d4ec', 'M0 470C150 456 280 470 420 440S600 352 700 346'],
  ['#0fb0d6', 'M0 522C160 506 300 520 450 496S620 432 700 422'],
  ['#0a8dba', 'M0 562C160 546 320 560 460 546S620 502 700 496'],
]

export function Mark({ size = 34 }: { size?: number }) {
  const id = 'mark' + useId().replace(/[^a-zA-Z0-9_-]/g, '')
  return (
    <svg
      className="mark"
      viewBox="35 45 630 585"
      width={size}
      height={(size * 585) / 630}
      aria-hidden="true"
    >
      <mask id={id}>
        <path d={markH} fill="#fff" />
        <path d={markGap} fill="none" stroke="#000" strokeWidth="16" />
      </mask>
      <g mask={`url(#${id})`}>
        <rect x="0" y="0" width="700" height="670" fill="#003e65" />
        {markBands
          .map(([fill, edge]) => (
            <path key={fill} d={`${edge}V0H0Z`} fill={fill} />
          ))
          .reverse()}
      </g>
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
        { path: '/mail', label: 'Mail domains', icon: Mail },
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
      items: [
        { path: '/users', label: 'Users', icon: Users, admin: true },
        { path: '/api-keys', label: 'API keys', icon: KeyRound, admin: true },
        {
          path: '/connections',
          label: 'External connections',
          icon: Plug,
          admin: true,
        },
      ],
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
  dns: 'External connections',
  mail: 'Mail domains',
  certificates: 'Certificates',
  honeypot: 'Honeypot',
  changes: 'Review & apply',
  history: 'History',
  audit: 'Audit',
  users: 'Users',
  account: 'Account',
  import: 'Import from NPM',
  'api-keys': 'API keys',
  connections: 'External connections',
  'api-docs': 'API reference',
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
