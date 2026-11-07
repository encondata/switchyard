import { useEffect, useMemo, useRef, useState } from 'react'
import {
  api,
  folderTree,
  message,
  type Folder,
  type HitRow,
  type HostView,
  type IPDetail,
  type StatsOverview,
  type StatsPoint,
  type StatsScope,
  type TopRow,
} from './api'

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

function pct(part: number, whole: number): string {
  if (!whole) return '0%'
  const p = (part / whole) * 100
  return `${p < 10 ? p.toFixed(1) : p.toFixed(0)}%`
}

function Tile({
  label,
  value,
  sub,
}: {
  label: string
  value: string
  sub?: string
}) {
  return (
    <div className="tile">
      <div className="tile-label">{label}</div>
      <div className="tile-value">{value}</div>
      {sub && <div className="tile-sub">{sub}</div>}
    </div>
  )
}

/** Stacked bars: allowed (series 1) and blocked (series 2) per time bucket. */
function TrafficChart({
  series,
  bucket,
}: {
  series: StatsPoint[]
  bucket: number
}) {
  const [hover, setHover] = useState<number | null>(null)
  const [table, setTable] = useState(false)
  const W = 720
  const H = 200
  const pad = { l: 44, r: 8, t: 8, b: 22 }
  const max = Math.max(1, ...series.map((p) => p.requests))
  // A "nice" top for the axis.
  const mag = 10 ** Math.floor(Math.log10(max))
  const top = Math.ceil(max / mag) * mag
  const bw = (W - pad.l - pad.r) / Math.max(1, series.length)
  const y = (v: number) => pad.t + (H - pad.t - pad.b) * (1 - v / top)
  const label = (t: string) => {
    const d = new Date(t)
    return bucket >= 86400
      ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  }
  const step = Math.max(1, Math.ceil(series.length / 6))
  const h = hover != null ? series[hover] : null

  return (
    <div className="viz">
      <div className="viz-head">
        <h2>Requests over time</h2>
        <div className="legend">
          <span>
            <i className="sw s1" /> Allowed
          </span>
          <span>
            <i className="sw s2" /> Blocked
          </span>
          <button className="link" onClick={() => setTable(!table)}>
            {table ? 'Show chart' : 'Show table'}
          </button>
        </div>
      </div>
      {table ? (
        <div className="table-wrap viz-table">
          <table>
            <thead>
              <tr>
                <th>Time</th>
                <th>Requests</th>
                <th>Blocked</th>
                <th>5xx</th>
                <th>Bandwidth</th>
              </tr>
            </thead>
            <tbody>
              {series.map((p) => (
                <tr key={p.t}>
                  <td>{new Date(p.t).toLocaleString()}</td>
                  <td>{fmt.format(p.requests)}</td>
                  <td>{fmt.format(p.blocked)}</td>
                  <td>{fmt.format(p.errors)}</td>
                  <td>{bytes(p.bytes)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="chart-wrap" onMouseLeave={() => setHover(null)}>
          <svg
            viewBox={`0 0 ${W} ${H}`}
            role="img"
            aria-label="Requests over time, allowed and blocked"
          >
            {[0, 0.5, 1].map((f) => (
              <g key={f}>
                <line
                  className="grid"
                  x1={pad.l}
                  x2={W - pad.r}
                  y1={y(top * f)}
                  y2={y(top * f)}
                />
                <text
                  className="axis"
                  x={pad.l - 6}
                  y={y(top * f) + 4}
                  textAnchor="end"
                >
                  {fmt.format(Math.round(top * f))}
                </text>
              </g>
            ))}
            {series.map((p, i) => {
              const x = pad.l + i * bw + 1
              const w = Math.max(1, bw - 2)
              const allowed = p.requests - p.blocked
              const ya = y(allowed)
              const yb = y(p.requests)
              return (
                <g key={p.t} onMouseEnter={() => setHover(i)}>
                  <rect
                    className="hit"
                    x={pad.l + i * bw}
                    y={pad.t}
                    width={bw}
                    height={H - pad.t - pad.b}
                  />
                  {allowed > 0 && (
                    <rect
                      className="bar s1"
                      x={x}
                      y={ya}
                      width={w}
                      height={y(0) - ya}
                      rx={Math.min(2, w / 2)}
                    />
                  )}
                  {p.blocked > 0 && (
                    <rect
                      className="bar s2"
                      x={x}
                      y={yb}
                      width={w}
                      height={Math.max(0, ya - yb - (allowed > 0 ? 1 : 0))}
                      rx={Math.min(2, w / 2)}
                    />
                  )}
                  {i % step === 0 && (
                    <text
                      className="axis"
                      x={x + w / 2}
                      y={H - 6}
                      textAnchor="middle"
                    >
                      {label(p.t)}
                    </text>
                  )}
                </g>
              )
            })}
            {hover != null && (
              <line
                className="crosshair"
                x1={pad.l + (hover + 0.5) * bw}
                x2={pad.l + (hover + 0.5) * bw}
                y1={pad.t}
                y2={y(0)}
              />
            )}
          </svg>
          {h && (
            <div
              className="tooltip"
              style={{ left: `${((pad.l + (hover! + 0.5) * bw) / W) * 100}%` }}
              role="status"
            >
              <strong>{new Date(h.t).toLocaleString()}</strong>
              <div>
                <i className="sw s1" /> Allowed{' '}
                {fmt.format(h.requests - h.blocked)}
              </div>
              <div>
                <i className="sw s2" /> Blocked {fmt.format(h.blocked)}
              </div>
              <div className="hint">
                5xx {fmt.format(h.errors)} · {bytes(h.bytes)}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function TopList({
  title,
  rows,
  keyLabel,
  onPick,
  render,
}: {
  title: string
  rows: TopRow[] | null
  keyLabel: string
  onPick?: (k: string) => void
  render?: (r: TopRow) => string
}) {
  const max = Math.max(1, ...(rows ?? []).map((r) => r.count))
  return (
    <div className="card toplist">
      <h2>{title}</h2>
      {!rows && <p className="hint">Loading…</p>}
      {rows?.length === 0 && <p className="hint">No traffic in this range.</p>}
      {rows && rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>{keyLabel}</th>
              <th className="num">Requests</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <td className="mono key-cell">
                  {onPick ? (
                    <button className="link mono" onClick={() => onPick(r.key)}>
                      {render ? render(r) : r.key}
                    </button>
                  ) : render ? (
                    render(r)
                  ) : (
                    r.key || '—'
                  )}
                  <div
                    className="inline-bar"
                    style={{ width: `${(r.count / max) * 100}%` }}
                  />
                </td>
                <td className="num">
                  {fmt.format(r.count)}
                  {r.blocked > 0 && (
                    <div className="hint">{fmt.format(r.blocked)} blocked</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function IPPanel({
  ip,
  canEdit,
  onClose,
}: {
  ip: string
  canEdit: boolean
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

  async function neverBlock() {
    try {
      await api.addNeverBan(ip, 'Added from the dashboard')
      setInfo(
        `${ip} is on the never-block list. Review and apply to send it to Caddy.`,
      )
      load()
    } catch (err) {
      setError(message(err))
    }
  }

  return (
    <div className="card ip-panel">
      <div className="toolbar">
        <h2 className="mono">{ip}</h2>
        <button className="link" onClick={onClose}>
          Close
        </button>
      </div>
      {error && <p className="error">{error}</p>}
      {info && <p className="success">{info}</p>}
      {d && (
        <>
          <p>
            {d.country && <>Country {d.country} · </>}
            {fmt.format(d.total)} requests, {fmt.format(d.blocked)} blocked
            (last 45 days)
            {d.never_ban && (
              <>
                {' '}
                · <span className="ok">never blocked</span>
              </>
            )}
          </p>
          {canEdit && !d.never_ban && (
            <div className="actions">
              <button className="secondary" onClick={neverBlock}>
                Never block this IP
              </button>
            </div>
          )}
          {d.hosts.length > 0 && (
            <p className="hint">
              Hosts:{' '}
              {d.hosts
                .map((h) => `${h.key} (${fmt.format(h.count)})`)
                .join(', ')}
            </p>
          )}
          <HitTable rows={d.recent} />
        </>
      )}
    </div>
  )
}

function HitTable({
  rows,
  onIP,
}: {
  rows: HitRow[]
  onIP?: (ip: string) => void
}) {
  return (
    <div className="table-wrap">
      <table className="hits">
        <thead>
          <tr>
            <th>Time</th>
            <th>Client</th>
            <th>Request</th>
            <th>Status</th>
            <th className="num">ms</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((h) => (
            <tr
              key={h.id}
              className={h.matched !== 'allowed' ? 'blocked-row' : ''}
            >
              <td>{new Date(h.ts).toLocaleTimeString()}</td>
              <td className="mono">
                {onIP ? (
                  <button
                    className="link mono"
                    onClick={() => onIP(h.client_ip)}
                  >
                    {h.client_ip}
                  </button>
                ) : (
                  h.client_ip
                )}{' '}
                {h.country && <span className="hint">{h.country}</span>}
              </td>
              <td className="mono req-cell">
                {h.method} {h.host}
                {h.path}
              </td>
              <td>
                {h.status || '—'}
                {h.matched !== 'allowed' && (
                  <div className="badge cert-expired">
                    {h.reason_text || h.matched}
                  </div>
                )}
              </td>
              <td className="num">{h.duration_ms.toFixed(0)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function LiveTail({
  scope,
  onIP,
}: {
  scope: StatsScope
  onIP: (ip: string) => void
}) {
  const [rows, setRows] = useState<HitRow[]>([])
  const [paused, setPaused] = useState(false)
  const last = useRef(0)

  useEffect(() => {
    if (paused) return
    let stop = false
    const tick = () =>
      api
        .statsTail(scope, last.current)
        .then((hs) => {
          if (stop || hs.length === 0) return
          last.current = hs[hs.length - 1].id
          setRows((r) => [...hs.reverse(), ...r].slice(0, 50))
        })
        .catch(() => undefined)
    void tick()
    const t = setInterval(tick, 3000)
    return () => {
      stop = true
      clearInterval(t)
    }
  }, [scope, paused])

  return (
    <div className="card">
      <div className="toolbar">
        <h2>Live</h2>
        <span className="hint">
          Newest first, updates every 3 seconds (latest 100 per update).
        </span>
        <button className="secondary" onClick={() => setPaused(!paused)}>
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>
      {rows.length === 0 ? (
        <p className="hint">Waiting for requests…</p>
      ) : (
        <HitTable rows={rows} onIP={onIP} />
      )}
    </div>
  )
}

export function Dashboard({ canEdit }: { canEdit: boolean }) {
  const [range, setRange] = useState('24h')
  const [host, setHost] = useState(0)
  const [folder, setFolder] = useState(0)
  const [hosts, setHosts] = useState<HostView[]>([])
  const [folders, setFolders] = useState<Folder[]>([])
  const [ov, setOv] = useState<StatsOverview | null>(null)
  const [top, setTop] = useState<Record<string, TopRow[] | null>>({})
  const [error, setError] = useState<string | null>(null)
  const [ip, setIP] = useState<string | null>(null)
  const scope = useMemo<StatsScope>(
    () => ({ range, host, folder }),
    [range, host, folder],
  )

  useEffect(() => {
    Promise.all([api.hosts(), api.folders()])
      .then(([h, f]) => {
        setHosts(h)
        setFolders(f)
      })
      .catch(() => undefined)
  }, [])

  useEffect(() => {
    api
      .statsOverview(scope)
      .then((o) => {
        setOv(o)
        setError(null)
      })
      .catch((err: unknown) => setError(message(err)))
    for (const dim of ['ip', 'country', 'path', 'status', 'host'])
      api
        .statsTop(scope, dim)
        .then((rows) => setTop((t) => ({ ...t, [dim]: rows })))
        .catch(() => setTop((t) => ({ ...t, [dim]: [] })))
  }, [scope])

  const o = ov?.overview
  return (
    <div className="stack">
      <div className="filters card">
        <h1>Dashboard</h1>
        <div className="segmented" role="group" aria-label="Time range">
          {['1h', '24h', '7d', '30d'].map((r) => (
            <button
              key={r}
              className={range === r ? '' : 'secondary'}
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
      {o && ov && (
        <div className="tiles">
          <Tile label="Requests" value={fmt.format(o.requests)} />
          <Tile label="Bandwidth" value={bytes(o.bytes)} />
          <Tile
            label="Server errors (5xx)"
            value={pct(o.errors, o.requests)}
            sub={`${fmt.format(o.errors)} requests`}
          />
          <Tile
            label="Blocked"
            value={pct(o.blocked, o.requests)}
            sub={`${fmt.format(o.blocked)} requests`}
          />
          <Tile
            label="Response time"
            value={
              ov.latency.samples ? `${ov.latency.p50_ms.toFixed(0)} ms` : '—'
            }
            sub={
              ov.latency.samples
                ? `p95 ${ov.latency.p95_ms.toFixed(0)} ms`
                : 'no data'
            }
          />
        </div>
      )}
      {o && (
        <div className="card">
          <TrafficChart series={o.series} bucket={o.bucket} />
        </div>
      )}
      {ip && <IPPanel ip={ip} canEdit={canEdit} onClose={() => setIP(null)} />}
      <div className="top-grid">
        <TopList
          title="Top IPs"
          keyLabel="IP"
          rows={top.ip ?? null}
          onPick={setIP}
          render={(r) => `${r.key}${r.country ? ` · ${r.country}` : ''}`}
        />
        <TopList
          title="Countries"
          keyLabel="Country"
          rows={top.country ?? null}
          render={(r) => r.key || 'Unknown'}
        />
        <TopList title="Top paths" keyLabel="Path" rows={top.path ?? null} />
        <TopList
          title="Status codes"
          keyLabel="Class"
          rows={top.status ?? null}
        />
        {!host && (
          <TopList title="Hosts" keyLabel="Host" rows={top.host ?? null} />
        )}
      </div>
      <LiveTail key={`${host}-${folder}`} scope={scope} onIP={setIP} />
      <p className="hint">
        Raw requests are kept 45 days; hourly totals (no IP addresses) 13
        months. Countries need the GeoLite2 database. A world map view is
        planned; the Countries list shows the same numbers.
      </p>
    </div>
  )
}
