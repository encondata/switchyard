import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Activity,
  ArrowDown,
  ArrowUp,
  ChartNoAxesColumnIncreasing,
  Code,
  FileText,
  Globe,
  House,
  Layers,
  List,
  Lock,
  Pause,
  Play,
  Plus,
  Server,
  ShieldCheck,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import {
  api,
  folderTree,
  message,
  type CertRow,
  type Country,
  type Folder,
  type HitRow,
  type HostView,
  type IPDetail,
  type StatsOverview,
  type StatsPoint,
  type StatsScope,
  type TopRow,
} from './api'
import { PageHeader } from './shell'

const fmt = new Intl.NumberFormat()

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const u = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${u[i]}`
}

function pct(part: number, whole: number, digits = 1): string {
  if (!whole) return '0%'
  return `${((part / whole) * 100).toFixed(digits)}%`
}

/** Emoji flag from an ISO country code. */
function flag(code: string): string {
  if (code === 'LAN') return '🏠'
  if (!/^[A-Z]{2}$/.test(code)) return '🌐'
  return String.fromCodePoint(
    ...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65),
  )
}

function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  trend,
}: {
  icon: LucideIcon
  label: string
  value: string
  sub?: string
  trend?: { text: string; good: boolean; up: boolean } | null
}) {
  return (
    <div className="stat">
      <span className="stat-icon" aria-hidden="true">
        <Icon size={22} strokeWidth={1.8} />
      </span>
      <div>
        <div className="stat-label">{label}</div>
        <div className="stat-value">{value}</div>
        {trend ? (
          <div className={`stat-sub ${trend.good ? 'good' : 'bad'}`}>
            {trend.up ? (
              <ArrowUp size={14} aria-hidden="true" />
            ) : (
              <ArrowDown size={14} aria-hidden="true" />
            )}
            {trend.text}
          </div>
        ) : (
          sub && <div className="stat-sub">{sub}</div>
        )}
      </div>
    </div>
  )
}

/** Smooth path through points (monotone-ish cubic). */
function smooth(pts: [number, number][]): string {
  if (pts.length === 0) return ''
  let d = `M${pts[0][0]},${pts[0][1]}`
  for (let i = 1; i < pts.length; i++) {
    const [x0, y0] = pts[i - 1]
    const [x1, y1] = pts[i]
    const cx = (x0 + x1) / 2
    d += ` C${cx},${y0} ${cx},${y1} ${x1},${y1}`
  }
  return d
}

/** Requests (area) and 5xx errors (line) over time, on one axis. */
function TrafficChart({
  series,
  bucket,
}: {
  series: StatsPoint[]
  bucket: number
}) {
  const [hover, setHover] = useState<number | null>(null)
  const [table, setTable] = useState(false)
  // Draw at the panel's real width so the chart fills it at any size.
  const [W, setW] = useState(760)
  const ro = useRef<ResizeObserver | null>(null)
  const measure = useCallback((el: HTMLDivElement | null) => {
    ro.current?.disconnect()
    if (!el) return
    const update = () => setW(Math.max(280, Math.round(el.clientWidth)))
    update()
    ro.current = new ResizeObserver(update)
    ro.current.observe(el)
  }, [])
  const H = 260
  const pad = { l: 48, r: 10, t: 10, b: 26 }
  const max = Math.max(1, ...series.map((p) => p.requests))
  const mag = 10 ** Math.floor(Math.log10(max))
  const step = Math.ceil(max / mag / 4) * mag
  const top = step * 4
  const iw = W - pad.l - pad.r
  const x = (i: number) =>
    pad.l + (series.length <= 1 ? iw / 2 : (i / (series.length - 1)) * iw)
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / top)
  const req: [number, number][] = series.map((p, i) => [x(i), y(p.requests)])
  const err: [number, number][] = series.map((p, i) => [x(i), y(p.errors)])
  const area = req.length
    ? `${smooth(req)} L${x(series.length - 1)},${y(0)} L${x(0)},${y(0)} Z`
    : ''
  const label = (t: string) => {
    const d = new Date(t)
    return bucket >= 86400
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  }
  const every = Math.max(
    1,
    Math.ceil(series.length / Math.max(2, Math.floor(W / 90))),
  )
  const h = hover != null ? series[hover] : null

  return (
    <div className="panel traffic">
      <div className="panel-head">
        <h2>Traffic overview</h2>
        <div className="legend">
          <span>
            <i className="sw s-req" /> Requests
          </span>
          <span>
            <i className="sw s-err" /> Errors (5xx)
          </span>
          <button className="link" onClick={() => setTable(!table)}>
            {table ? 'Chart' : 'Table'}
          </button>
        </div>
      </div>
      {table ? (
        <div className="table-wrap viz-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th className="num">Requests</th>
                <th className="num">Errors</th>
                <th className="num">Blocked</th>
                <th className="num">Bandwidth</th>
              </tr>
            </thead>
            <tbody>
              {series.map((p) => (
                <tr key={p.t}>
                  <td>{new Date(p.t).toLocaleString()}</td>
                  <td className="num">{fmt.format(p.requests)}</td>
                  <td className="num">{fmt.format(p.errors)}</td>
                  <td className="num">{fmt.format(p.blocked)}</td>
                  <td className="num">{bytes(p.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          className="chart-wrap"
          ref={measure}
          onMouseLeave={() => setHover(null)}
        >
          <svg
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label="Requests and server errors over time"
          >
            {[0, 1, 2, 3, 4].map((k) => (
              <g key={k}>
                <line
                  className="grid"
                  x1={pad.l}
                  x2={W - pad.r}
                  y1={y(step * k)}
                  y2={y(step * k)}
                />
                <text
                  className="axis"
                  x={pad.l - 8}
                  y={y(step * k) + 4}
                  textAnchor="end"
                >
                  {fmt.format(step * k)}
                </text>
              </g>
            ))}
            <path className="area-req" d={area} />
            <path className="line-req" d={smooth(req)} />
            <path className="line-err" d={smooth(err)} />
            {series.map((p, i) =>
              i % every === 0 ? (
                <text
                  key={p.t}
                  className="axis"
                  x={x(i)}
                  y={H - 6}
                  textAnchor="middle"
                >
                  {label(p.t)}
                </text>
              ) : null,
            )}
            {series.map((p, i) => (
              <rect
                key={'hit' + p.t}
                className="hit"
                x={x(i) - iw / Math.max(1, series.length) / 2}
                y={pad.t}
                width={iw / Math.max(1, series.length)}
                height={H - pad.t - pad.b}
                onMouseEnter={() => setHover(i)}
              />
            ))}
            {h && hover != null && (
              <g>
                <line
                  className="crosshair"
                  x1={x(hover)}
                  x2={x(hover)}
                  y1={pad.t}
                  y2={y(0)}
                />
                <circle
                  className="dot-req"
                  cx={x(hover)}
                  cy={y(h.requests)}
                  r={4.5}
                />
                <circle
                  className="dot-err"
                  cx={x(hover)}
                  cy={y(h.errors)}
                  r={4}
                />
              </g>
            )}
          </svg>
          {h && hover != null && (
            <div
              className="tooltip"
              style={{ left: `${(x(hover) / W) * 100}%` }}
              role="status"
            >
              <strong>{new Date(h.t).toLocaleString()}</strong>
              <div>
                <i className="sw s-req" /> {fmt.format(h.requests)} requests
              </div>
              <div>
                <i className="sw s-err" /> {fmt.format(h.errors)} errors
              </div>
              <div className="hint">
                {fmt.format(h.blocked)} blocked · {bytes(h.bytes)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const codeClasses: { key: string; label: string; cls: string }[] = [
  { key: '2xx', label: '2xx success', cls: 'c2' },
  { key: '3xx', label: '3xx redirection', cls: 'c3' },
  { key: '4xx', label: '4xx client error', cls: 'c4' },
  { key: '5xx', label: '5xx server error', cls: 'c5' },
  { key: 'no response', label: 'No response (dropped)', cls: 'c0' },
]

function ResponseCodes({ rows }: { rows: TopRow[] | null }) {
  const counts = new Map((rows ?? []).map((r) => [r.key, r.count]))
  const total = [...counts.values()].reduce((a, b) => a + b, 0)
  const shown = codeClasses.filter(
    (c) => c.key !== 'no response' || counts.get(c.key),
  )
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Response codes</h2>
      </div>
      {!rows ? (
        <p className="hint">Loading…</p>
      ) : total === 0 ? (
        <p className="hint">No requests in this range.</p>
      ) : (
        <>
          <div
            className="codes-bar"
            role="img"
            aria-label="Share of responses by status class"
          >
            {shown.map((c) => {
              const n = counts.get(c.key) ?? 0
              return n ? (
                <span
                  key={c.key}
                  className={c.cls}
                  style={{ flexGrow: n }}
                  title={`${c.label}: ${pct(n, total)}`}
                />
              ) : null
            })}
          </div>
          <table className="codes">
            <tbody>
              {shown.map((c) => {
                const n = counts.get(c.key) ?? 0
                return (
                  <tr key={c.key}>
                    <td>
                      <i className={`code-dot ${c.cls}`} /> {c.label}
                    </td>
                    <td className="num">{pct(n, total)}</td>
                    <td className="num">{fmt.format(n)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </>
      )}
    </div>
  )
}

function pathIcon(p: string): LucideIcon {
  if (p === '/') return House
  if (/login|signin|auth|account/i.test(p)) return Lock
  if (/^\/(api|v\d)/i.test(p)) return Code
  return FileText
}

function TopTable({
  title,
  keyLabel,
  rows,
  icon,
  onPick,
}: {
  title: string
  keyLabel: string
  rows: TopRow[] | null
  icon: (r: TopRow) => LucideIcon
  onPick?: (k: string) => void
}) {
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>{title}</h2>
      </div>
      {!rows ? (
        <p className="hint">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="hint">No traffic in this range.</p>
      ) : (
        <table className="top">
          <thead>
            <tr>
              <th>{keyLabel}</th>
              <th className="num">Requests</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 6).map((r) => {
              const Icon = icon(r)
              return (
                <tr key={r.key}>
                  <td>
                    <div className="key">
                      <Icon size={17} strokeWidth={1.8} aria-hidden="true" />
                      {onPick ? (
                        <button className="link" onClick={() => onPick(r.key)}>
                          {r.key || '—'}
                        </button>
                      ) : (
                        <span>{r.key || '—'}</span>
                      )}
                    </div>
                  </td>
                  <td className="num">{fmt.format(r.count)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

function Countries({
  rows,
  names,
  source,
}: {
  rows: TopRow[] | null
  names: Map<string, string>
  source?: string
}) {
  const total = (rows ?? []).reduce((a, r) => a + r.count, 0)
  const max = Math.max(1, ...(rows ?? []).map((r) => r.count))
  return (
    <div className="panel">
      <div className="panel-head">
        <h2>Countries</h2>
      </div>
      {!rows ? (
        <p className="hint">Loading…</p>
      ) : rows.length === 0 ? (
        <p className="hint">No traffic in this range.</p>
      ) : (
        <table className="top">
          <thead>
            <tr>
              <th>Country</th>
              <th aria-label="Share bar" />
              <th className="num">Requests</th>
              <th className="num">Share</th>
            </tr>
          </thead>
          <tbody>
            {rows.slice(0, 6).map((r) => (
              <tr key={r.key}>
                <td>
                  <div className="key">
                    <span className="flag" aria-hidden="true">
                      {flag(r.key)}
                    </span>
                    <span>
                      {r.key ? (names.get(r.key) ?? r.key) : 'Unknown'}
                    </span>
                  </div>
                </td>
                <td className="bar-cell">
                  <span className="share-track">
                    <span
                      className="share-fill"
                      style={{ width: `${(r.count / max) * 100}%` }}
                    />
                  </span>
                </td>
                <td className="num">{fmt.format(r.count)}</td>
                <td className="num">{pct(r.count, total)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {source === 'DB-IP' && (
        <p className="credit">
          <a href="https://db-ip.com" target="_blank" rel="noreferrer">
            IP Geolocation by DB-IP
          </a>
        </p>
      )}
    </div>
  )
}

function StatusPill({ h }: { h: HitRow }) {
  if (h.matched !== 'allowed')
    return (
      <span className="pill pill-blocked" title={h.reason_text}>
        {h.matched === 'honeypot' ? 'Honeypot' : 'Blocked'}
      </span>
    )
  const cls =
    h.status >= 500
      ? 'pill-5'
      : h.status >= 400
        ? 'pill-4'
        : h.status >= 300
          ? 'pill-3'
          : 'pill-2'
  return <span className={`pill ${cls}`}>{h.status || '—'}</span>
}

function HitTable({
  rows,
  names,
  onIP,
}: {
  rows: HitRow[]
  names: Map<string, string>
  onIP?: (ip: string) => void
}) {
  return (
    <div className="table-wrap">
      <table className="hits">
        <thead>
          <tr>
            <th>Time</th>
            <th>Host</th>
            <th>Client IP</th>
            <th>Country</th>
            <th>Path</th>
            <th>Status</th>
            <th className="num">Duration</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((h) => (
            <tr key={h.id}>
              <td className="nowrap">{new Date(h.ts).toLocaleString()}</td>
              <td>
                <div className="key">
                  <Globe size={16} strokeWidth={1.8} aria-hidden="true" />
                  <span>{h.host}</span>
                </div>
              </td>
              <td className="nowrap">
                {onIP ? (
                  <button className="link" onClick={() => onIP(h.client_ip)}>
                    {h.client_ip}
                  </button>
                ) : (
                  h.client_ip
                )}
              </td>
              <td className="nowrap">
                {h.country ? (
                  <>
                    <span className="flag" aria-hidden="true">
                      {flag(h.country)}
                    </span>{' '}
                    {names.get(h.country) ?? h.country}
                  </>
                ) : (
                  <span className="hint">—</span>
                )}
              </td>
              <td className="path-cell" title={h.method + ' ' + h.path}>
                {h.path}
              </td>
              <td>
                <StatusPill h={h} />
              </td>
              <td className="num nowrap">{h.duration_ms.toFixed(0)} ms</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function IPPanel({
  ip,
  canEdit,
  names,
  onClose,
}: {
  ip: string
  canEdit: boolean
  names: Map<string, string>
  onClose: () => void
}) {
  const [d, setD] = useState<IPDetail | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)

  function load() {
    api
      .statsIP(ip)
      .then(setD)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [ip])

  async function act(
    fn: () => Promise<{ warning?: string } | unknown>,
    done: string,
  ) {
    setError(null)
    try {
      const r = (await fn()) as { warning?: string } | undefined
      setInfo(r && r.warning ? r.warning : done)
      load()
    } catch (err) {
      setError(message(err))
    }
  }

  return (
    <div className="panel ip-panel">
      <div className="panel-head">
        <h2>{ip}</h2>
        <button className="link" onClick={onClose}>
          Close
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {info && <p className="success">{info}</p>}
      {d && (
        <>
          <p>
            {d.country && (
              <>
                {flag(d.country)} {names.get(d.country) ?? d.country} ·{' '}
              </>
            )}
            {fmt.format(d.total)} requests, {fmt.format(d.blocked)} blocked in
            the last 45 days
            {d.never_ban && <span className="ok"> · never blocked</span>}
            {d.banned && <span className="bad"> · banned</span>}
          </p>
          {canEdit && (
            <div className="actions">
              {!d.never_ban && (
                <button
                  className="secondary"
                  onClick={() =>
                    act(
                      () => api.addNeverBan(ip, 'Added from the dashboard'),
                      `${ip} is on the never-block list. Review and apply to send it to Caddy.`,
                    )
                  }
                >
                  Never block this IP
                </button>
              )}
              {!d.never_ban && !d.banned && (
                <button
                  className="secondary danger"
                  onClick={() =>
                    act(
                      () => api.addBan(ip, 'Banned from the dashboard', 7),
                      `${ip} is banned on every host.`,
                    )
                  }
                >
                  Ban for 7 days
                </button>
              )}
              {d.banned && (
                <button
                  className="secondary"
                  onClick={() =>
                    act(() => api.unbanAddress(ip), `Lifted the ban on ${ip}.`)
                  }
                >
                  Lift ban
                </button>
              )}
            </div>
          )}
          {d.recent.length > 0 && (
            <HitTable rows={d.recent.slice(0, 20)} names={names} />
          )}
        </>
      )}
    </div>
  )
}

function LiveAndTopIPs({
  scope,
  names,
  topIPs,
  onIP,
}: {
  scope: StatsScope
  names: Map<string, string>
  topIPs: TopRow[] | null
  onIP: (ip: string) => void
}) {
  const [tab, setTab] = useState<'live' | 'ips'>('live')
  const [rows, setRows] = useState<HitRow[]>([])
  const [paused, setPaused] = useState(false)
  const last = useRef(0)

  useEffect(() => {
    if (paused || tab !== 'live') return
    let stop = false
    const tick = () =>
      api
        .statsTail(scope, last.current)
        .then((hs) => {
          if (stop || hs.length === 0) return
          last.current = hs[hs.length - 1].id
          setRows((r) => [...hs.reverse(), ...r].slice(0, 15))
        })
        .catch(() => undefined)
    void tick()
    const t = setInterval(tick, 3000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [scope, paused, tab])

  return (
    <div className="panel">
      <div className="tabs-head">
        <div className="tabs" role="tablist">
          <button
            role="tab"
            aria-selected={tab === 'live'}
            className={tab === 'live' ? 'active' : ''}
            onClick={() => setTab('live')}
          >
            <span
              className={`live-dot${paused ? ' paused' : ''}`}
              aria-hidden="true"
            />{' '}
            Live requests
          </button>
          <button
            role="tab"
            aria-selected={tab === 'ips'}
            className={tab === 'ips' ? 'active' : ''}
            onClick={() => setTab('ips')}
          >
            <Layers size={16} strokeWidth={1.8} aria-hidden="true" /> Top IPs
          </button>
        </div>
        {tab === 'live' && (
          <div className="tabs-tools">
            <span className="hint">Updates every 3s</span>
            <button
              className="secondary small"
              onClick={() => setPaused(!paused)}
            >
              {paused ? (
                <Play size={14} aria-hidden="true" />
              ) : (
                <Pause size={14} aria-hidden="true" />
              )}
              {paused ? 'Resume' : 'Pause'}
            </button>
          </div>
        )}
      </div>
      {tab === 'live' ? (
        rows.length === 0 ? (
          <p className="hint empty-line">Waiting for requests…</p>
        ) : (
          <HitTable rows={rows} names={names} onIP={onIP} />
        )
      ) : !topIPs || topIPs.length === 0 ? (
        <p className="hint empty-line">No traffic in this range.</p>
      ) : (
        <div className="table-wrap">
          <table className="hits">
            <thead>
              <tr>
                <th>Client IP</th>
                <th>Country</th>
                <th className="num">Requests</th>
                <th className="num">Blocked</th>
              </tr>
            </thead>
            <tbody>
              {topIPs.map((r) => (
                <tr key={r.key}>
                  <td>
                    <button className="link" onClick={() => onIP(r.key)}>
                      {r.key}
                    </button>
                  </td>
                  <td>
                    {r.country ? (
                      <>
                        <span className="flag" aria-hidden="true">
                          {flag(r.country)}
                        </span>{' '}
                        {names.get(r.country) ?? r.country}
                      </>
                    ) : (
                      <span className="hint">—</span>
                    )}
                  </td>
                  <td className="num">{fmt.format(r.count)}</td>
                  <td className="num">{fmt.format(r.blocked)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export function Dashboard({
  canEdit,
  route,
}: {
  canEdit: boolean
  route: string
  pending: number
}) {
  const [range, setRange] = useState('24h')
  const [host, setHost] = useState(0)
  const [folder, setFolder] = useState(0)
  const [hosts, setHosts] = useState<HostView[]>([])
  const [folders, setFolders] = useState<Folder[]>([])
  const [certs, setCerts] = useState<CertRow[] | null>(null)
  const [names, setNames] = useState(
    new Map<string, string>([['LAN', 'Local network']]),
  )
  const [ov, setOv] = useState<
    | (StatsOverview & {
        previous?: { requests: number; errors: number }
        geo_source?: string
      })
    | null
  >(null)
  const [top, setTop] = useState<Record<string, TopRow[] | null>>({})
  const [error, setError] = useState<string | null>(null)
  const ipFromRoute = new URLSearchParams(route.split('?')[1] ?? '').get('ip')
  const [ip, setIP] = useState<string | null>(ipFromRoute)
  const scope = useMemo<StatsScope>(
    () => ({ range, host, folder }),
    [range, host, folder],
  )

  useEffect(() => {
    if (ipFromRoute) setIP(ipFromRoute) // eslint-disable-line react-hooks/set-state-in-effect
  }, [ipFromRoute])

  useEffect(() => {
    api
      .hosts()
      .then(setHosts)
      .catch(() => undefined)
    api
      .folders()
      .then(setFolders)
      .catch(() => undefined)
    api
      .certificates()
      .then(setCerts)
      .catch(() => setCerts([]))
    api
      .countries()
      .then((cs: Country[]) =>
        setNames(
          new Map([
            ['LAN', 'Local network'],
            ...cs.map((c): [string, string] => [c.code, c.name]),
          ]),
        ),
      )
      .catch(() => undefined)
  }, [])

  // Load now and refresh every minute while the page is open.
  useEffect(() => {
    const load = () => {
      api
        .statsOverview(scope)
        .then((o) => {
          setOv(o)
          setError(null)
        })
        .catch((err: unknown) => setError(message(err)))
      for (const dim of ['ip', 'country', 'path', 'status', 'host'])
        api
          .statsTop(scope, dim, 10)
          .then((rows) => setTop((t) => ({ ...t, [dim]: rows })))
          .catch(() => setTop((t) => ({ ...t, [dim]: [] })))
    }
    load()
    const t = setInterval(load, 60_000)
    return () => clearInterval(t)
  }, [scope])

  const o = ov?.overview
  const prev = ov?.previous
  const reqTrend =
    o && prev && prev.requests > 0
      ? (() => {
          const ch = ((o.requests - prev.requests) / prev.requests) * 100
          return {
            text: `${ch >= 0 ? '+' : ''}${ch.toFixed(1)}% vs previous ${range}`,
            up: ch >= 0,
            good: true,
          }
        })()
      : null
  const errRate = o && o.requests ? (o.errors / o.requests) * 100 : 0
  const errTrend =
    o && prev && prev.requests > 0
      ? (() => {
          const ch = errRate - (prev.errors / prev.requests) * 100
          return {
            text: `${ch >= 0 ? '+' : ''}${ch.toFixed(2)} pp vs previous ${range}`,
            up: ch > 0,
            good: ch <= 0,
          }
        })()
      : null
  const enabled = hosts.filter((h) => h.enabled).length
  const validCerts = certs?.filter((c) => c.state === 'valid').length ?? 0
  const badCerts = certs?.filter((c) => c.state !== 'valid').length ?? 0

  return (
    <div className="page">
      <PageHeader
        title="Dashboard"
        subtitle="Traffic across every host Caddy serves."
        actions={
          <>
            <a className="button secondary" href="#/hosts">
              <List size={18} aria-hidden="true" /> View hosts
            </a>
            {canEdit && (
              <a className="button" href="#/hosts/new">
                <Plus size={18} aria-hidden="true" /> Add host
              </a>
            )}
          </>
        }
      />

      <div className="filters">
        <div className="seg" role="group" aria-label="Time range">
          {['1h', '24h', '7d', '30d'].map((r) => (
            <button
              key={r}
              className={range === r ? 'active' : ''}
              aria-pressed={range === r}
              onClick={() => setRange(r)}
            >
              {r}
            </button>
          ))}
        </div>
        <select
          aria-label="Host"
          value={host}
          onChange={(e) => {
            setHost(Number(e.target.value))
            setFolder(0)
          }}
        >
          <option value={0}>All hosts</option>
          {hosts.map((h) => (
            <option key={h.id} value={h.id}>
              {h.domains[0]}
            </option>
          ))}
        </select>
        <select
          aria-label="Folder"
          value={folder}
          onChange={(e) => {
            setFolder(Number(e.target.value))
            setHost(0)
          }}
        >
          <option value={0}>All folders</option>
          {folderTree(folders).map(({ folder: f, depth }) => (
            <option key={f.id} value={f.id}>
              {'  '.repeat(depth)}
              {f.name}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="stats">
        <StatCard
          icon={ChartNoAxesColumnIncreasing}
          label="Requests"
          value={o ? fmt.format(o.requests) : '—'}
          sub={o ? `${bytes(o.bytes)} transferred` : undefined}
          trend={reqTrend}
        />
        <StatCard
          icon={Server}
          label="Active hosts"
          value={`${enabled}/${hosts.length}`}
          sub={
            hosts.length === 0
              ? 'No hosts yet'
              : enabled === hosts.length
                ? 'All enabled'
                : `${hosts.length - enabled} disabled`
          }
        />
        <StatCard
          icon={TriangleAlert}
          label="Error rate"
          value={o ? `${errRate.toFixed(2)}%` : '—'}
          sub={o ? `${fmt.format(o.errors)} server errors` : undefined}
          trend={errTrend}
        />
        <StatCard
          icon={ShieldCheck}
          label="Certificates"
          value={certs ? `${validCerts} valid` : '—'}
          sub={
            certs
              ? certs.length === 0
                ? 'No HTTPS hosts yet'
                : badCerts === 0
                  ? 'All certificates healthy'
                  : `${badCerts} need attention`
              : undefined
          }
        />
      </div>

      <div className="grid-2">
        {o ? (
          <TrafficChart series={o.series} bucket={o.bucket} />
        ) : (
          <div className="panel">Loading…</div>
        )}
        <ResponseCodes rows={top.status ?? null} />
      </div>

      {ip && (
        <IPPanel
          ip={ip}
          canEdit={canEdit}
          names={names}
          onClose={() => setIP(null)}
        />
      )}

      <div className="grid-3">
        <TopTable
          title="Top hosts"
          keyLabel="Host"
          rows={top.host ?? null}
          icon={() => Globe}
        />
        <Countries
          rows={top.country ?? null}
          names={names}
          source={ov?.geo_source}
        />
        <TopTable
          title="Top paths"
          keyLabel="Path"
          rows={top.path ?? null}
          icon={(r) => pathIcon(r.key)}
        />
      </div>

      <LiveAndTopIPs
        key={`${host}-${folder}`}
        scope={scope}
        names={names}
        topIPs={top.ip ?? null}
        onIP={setIP}
      />

      <p className="footnote">
        <Activity size={14} aria-hidden="true" /> Raw requests are kept for 45
        days; hourly totals for 13 months.
      </p>
    </div>
  )
}
