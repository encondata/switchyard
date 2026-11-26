import { useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import {
  Activity,
  Crosshair,
  FileText,
  History,
  KeyRound,
  LayoutGrid,
  Layers,
  Lock,
  Mail,
  Plug,
  Search,
  ShieldCheck,
  UserCog,
  Users,
  type LucideIcon,
} from 'lucide-react'
import {
  api,
  type Alert,
  type AuthConfig,
  type HostView,
  type User,
} from './api'
import { NotificationBell } from './notify'
import markUrl from './hsl-ui/mark.svg'

/** The HackSpaceLabs H, from the HSL Suite kit. Decorative: always next to a name. */
export function Mark({ size = 34 }: { size?: number }) {
  return (
    <img
      className="hsl-mark"
      src={markUrl}
      width={size}
      height={Math.round((size * 585) / 630)}
      alt=""
    />
  )
}

/** Mark and wordmark, linking home. */
export function Logo() {
  return (
    <a className="hsl-brand" href="#/dashboard" aria-label="Switchyard home">
      <Mark />
      <span className="hsl-wordmark">Switchyard</span>
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
}: {
  route: string
  user: User
  pending: number
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
    <aside className="hsl-sidebar">
      <Logo />
      <nav className="hsl-nav" aria-label="Main">
        {groups.map((g) => {
          const items = g.items.filter((i) => !i.admin || isAdmin)
          if (items.length === 0) return null
          return (
            <div className="hsl-nav-group" key={g.title}>
              <div className="hsl-nav-label">{g.title}</div>
              {items.map((i) => (
                <a
                  key={i.path}
                  href={`#${i.path}`}
                  className="hsl-nav-item"
                  aria-current={active(i.path) ? 'page' : undefined}
                >
                  <i.icon size={19} strokeWidth={1.8} aria-hidden="true" />
                  <span>{i.label}</span>
                  {!!i.badge && (
                    <span
                      className="hsl-nav-badge"
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
      {/* Switchyard's own account page: password, two-factor sign-in, accent colour. */}
      <div className="hsl-sidebar-foot">
        <a
          className="hsl-nav-item"
          href="#/account"
          title="Your account, two-factor sign-in and accent colour"
          aria-current={route === '/account' ? 'page' : undefined}
        >
          <UserCog size={19} strokeWidth={1.8} aria-hidden="true" />
          <span>Account</span>
        </a>
      </div>
    </aside>
  )
}

const roleNames: Record<User['role'], string> = {
  admin: 'Administrator',
  editor: 'Editor',
  viewer: 'Viewer',
}

/**
 * The kit's user menu: name, role, Profile, dark mode, Sign out. Profile is the HackSpaceLabs
 * portal's /me for HackSpaceLabs accounts, and Switchyard's own account page for local ones.
 */
function UserMenu({
  user,
  config,
  onSignOut,
}: {
  user: User
  config: AuthConfig | null
  onSignOut: () => void
}) {
  const ref = useRef<HTMLElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const out = () => onSignOut()
    el.addEventListener('hsl-signout', out)
    return () => el.removeEventListener('hsl-signout', out)
  }, [onSignOut])
  const hsl = user.auth_source === 'oidc'
  const profile =
    hsl && config?.portal_url ? config.portal_url + '/me' : '/#/account'
  return (
    <hsl-user-menu
      ref={ref}
      name={user.display_name || user.username}
      detail={
        roleNames[user.role] + (hsl ? ' · HackSpaceLabs' : ' · Local account')
      }
      profile-url={profile}
    />
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
    <a
      href="#/health"
      className={`caddy-status ${ok ? 'up' : 'down'}`}
      title={ok ? 'Caddy online' : 'Caddy unreachable'}
    >
      <span className="status-dot" aria-hidden="true" />
      <span className="caddy-status-label">
        {ok ? 'Caddy online' : 'Caddy unreachable'}
      </span>
    </a>
  )
}

export function Topbar({
  route,
  alerts,
  user,
  config,
  onSignOut,
}: {
  route: string
  alerts: Alert[] | null
  user: User
  config: AuthConfig | null
  onSignOut: () => void
}) {
  const section = route.split(/[/?]/)[1] || 'dashboard'
  const name = pageNames[section] ?? 'Dashboard'
  const sub = route.startsWith('/hosts/new')
    ? 'New host'
    : /^\/hosts\/\d+/.test(route)
      ? 'Edit host'
      : null
  return (
    <header className="hsl-topbar">
      <div className="hsl-topbar-title">
        <a href="#/dashboard">Switchyard</a>
        <span className="hsl-topbar-sep" aria-hidden="true">
          /
        </span>
        {sub ? (
          <>
            <a href={`#/${section}`}>{name}</a>
            <span className="hsl-topbar-sep" aria-hidden="true">
              /
            </span>
            <strong>{sub}</strong>
          </>
        ) : (
          <strong>{name}</strong>
        )}
      </div>
      <GlobalSearch />
      <NotificationBell
        key={user.username}
        alerts={alerts}
        username={user.username}
      />
      <CaddyStatus />
      <div className="hsl-topbar-end">
        <hsl-app-switcher
          current="switchyard"
          apps={JSON.stringify(config?.apps ?? [])}
        />
        <UserMenu user={user} config={config} onSignOut={onSignOut} />
      </div>
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
