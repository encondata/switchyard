import { UniFiCard } from './unificard'
import { useEffect, useState, type FormEvent } from 'react'
import {
  api,
  ApiError,
  message,
  type Ban,
  type HoneypotActivity,
  type HoneypotSettings,
  type TopRow,
  type TrapPath,
} from './api'

const fmt = new Intl.NumberFormat()

function Mini({
  title,
  rows,
  mono = true,
}: {
  title: string
  rows: TopRow[]
  mono?: boolean
}) {
  const max = Math.max(1, ...rows.map((r) => r.count))
  return (
    <div className="card toplist">
      <h2>{title}</h2>
      {rows.length === 0 ? (
        <p className="hint">Nothing yet.</p>
      ) : (
        <table>
          <tbody>
            {rows.map((r) => (
              <tr key={r.key}>
                <td className={`key-cell${mono ? ' mono' : ''}`}>
                  {r.key || '—'}
                  {r.country && <span className="hint"> · {r.country}</span>}
                  <div
                    className="inline-bar"
                    style={{ width: `${(r.count / max) * 100}%` }}
                  />
                </td>
                <td className="num">{fmt.format(r.count)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}

function CrowdSecCard({ onChanged }: { onChanged: () => void }) {
  const [c, setC] = useState<{
    enabled: boolean
    api_url: string
    key_set: boolean
  } | null>(null)
  const [key, setKey] = useState('')
  const [msg, setMsg] = useState<string | null>(null)
  const [err, setErr] = useState<string | null>(null)
  useEffect(() => {
    api
      .crowdsec()
      .then(setC)
      .catch(() => setC(null))
  }, [])
  if (!c) return null
  return (
    <section className="card">
      <h1>CrowdSec (optional)</h1>
      <p className="hint">
        Also block addresses on CrowdSec’s community block lists. Needs a
        CrowdSec Local API you run (e.g. the crowdsec container) and a bouncer
        key from <code>cscli bouncers add cpm</code>. Checked after CPM’s own
        bans; never-block addresses are skipped.
      </p>
      {err && <p className="error">{err}</p>}
      {msg && <p className="success">{msg}</p>}
      <form
        className="folder-form"
        onSubmit={(e) => {
          e.preventDefault()
          setErr(null)
          api
            .saveCrowdSec(c.enabled, c.api_url, key)
            .then((r) => {
              setC(r)
              setKey('')
              setMsg('Saved. Review and apply to send it to Caddy.')
              onChanged()
            })
            .catch((x: unknown) =>
              setErr(
                x instanceof ApiError && Object.keys(x.fields).length
                  ? Object.values(x.fields).join(' ')
                  : message(x),
              ),
            )
        }}
      >
        <label className="inline">
          <input
            type="checkbox"
            checked={c.enabled}
            onChange={(e) => setC({ ...c, enabled: e.target.checked })}
          />
          Use CrowdSec
        </label>
        <label>
          Local API address
          <input
            className="mono"
            placeholder="http://crowdsec:8080/"
            value={c.api_url}
            onChange={(e) => setC({ ...c, api_url: e.target.value })}
          />
        </label>
        <label>
          Bouncer key{' '}
          {c.key_set && (
            <span className="hint">(saved; leave empty to keep it)</span>
          )}
          <input
            type="password"
            autoComplete="off"
            className="mono"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
        </label>
        <div className="actions">
          <button>Save</button>
        </div>
      </form>
    </section>
  )
}

export function HoneypotPage({
  canEdit,
  isAdmin = false,
  onChanged,
}: {
  canEdit: boolean
  isAdmin?: boolean
  onChanged: () => void
}) {
  const [settings, setSettings] = useState<HoneypotSettings | null>(null)
  const [traps, setTraps] = useState<TrapPath[]>([])
  const [bans, setBans] = useState<Ban[]>([])
  const [showAll, setShowAll] = useState(false)
  const [activity, setActivity] = useState<HoneypotActivity | null>(null)
  const [range, setRange] = useState('24h')
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [newTrap, setNewTrap] = useState({ pattern: '', score: 10 })
  const [ban, setBan] = useState({ cidr: '', reason: '', days: 7 })

  function load() {
    api
      .honeypot()
      .then((r) => {
        setSettings(r.settings)
        setTraps(r.traps)
      })
      .catch((err: unknown) => setError(message(err)))
    api
      .bans(showAll)
      .then(setBans)
      .catch(() => undefined)
  }
  useEffect(load, [showAll])
  useEffect(() => {
    api
      .honeypotActivity(range)
      .then(setActivity)
      .catch(() => undefined)
  }, [range])

  async function run(
    fn: () => Promise<unknown>,
    done: string,
    configChange = false,
  ) {
    setError(null)
    setInfo(null)
    setFields({})
    try {
      const r = (await fn()) as { warning?: string } | undefined
      setInfo(r && r.warning ? r.warning : done)
      load()
      if (configChange) onChanged()
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  async function saveSettings(e: FormEvent) {
    e.preventDefault()
    if (settings)
      await run(
        () => api.saveHoneypot(settings),
        'Saved. Review and apply to send the honeypot to Caddy.',
        true,
      )
  }

  const num =
    (k: keyof HoneypotSettings) => (e: { target: { value: string } }) =>
      settings && setSettings({ ...settings, [k]: Number(e.target.value) })

  return (
    <div className="stack">
      <section className="card">
        <h1>Honeypot</h1>
        <p className="hint">
          Requests for names CPM doesn’t serve (and bare-IP requests) go to a
          catch-all that serves a fake page. Requests for known scanner paths on
          any host go there too. Each hit earns points; an address that crosses
          the threshold is banned on every host. Addresses on the never-block
          list are never banned. The honeypot only serves static content.
        </p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {info && (
          <p className="success" role="status">
            {info}
          </p>
        )}
        {settings && (
          <form className="folder-form" onSubmit={saveSettings}>
            <label className="inline">
              <input
                type="checkbox"
                disabled={!canEdit}
                checked={settings.enabled}
                onChange={(e) =>
                  setSettings({ ...settings, enabled: e.target.checked })
                }
              />
              <strong>Honeypot on</strong>
            </label>
            <label>
              Fake response
              <select
                disabled={!canEdit}
                value={settings.response}
                onChange={(e) =>
                  setSettings({
                    ...settings,
                    response: e.target.value as HoneypotSettings['response'],
                  })
                }
              >
                <option value="login">A generic sign-in page</option>
                <option value="server">
                  A default “It works!” server page
                </option>
                <option value="empty">An empty 200 response</option>
                <option value="404">A plain 404</option>
              </select>
            </label>
            <div className="actions">
              <label>
                Points per catch-all hit
                <input
                  type="number"
                  min={0}
                  disabled={!canEdit}
                  value={settings.catchall_score}
                  onChange={num('catchall_score')}
                />
              </label>
              <label>
                Ban at
                <input
                  type="number"
                  min={1}
                  disabled={!canEdit}
                  value={settings.threshold}
                  onChange={num('threshold')}
                />
                {fields.threshold && (
                  <span className="field-error">{fields.threshold}</span>
                )}
              </label>
              <label>
                points within (hours)
                <input
                  type="number"
                  min={1}
                  disabled={!canEdit}
                  value={settings.window_hours}
                  onChange={num('window_hours')}
                />
              </label>
            </div>
            <div className="actions">
              <label>
                First ban (days)
                <input
                  type="number"
                  min={1}
                  disabled={!canEdit}
                  value={settings.ban_days}
                  onChange={num('ban_days')}
                />
              </label>
              <label>
                Longest ban (days)
                <input
                  type="number"
                  min={1}
                  disabled={!canEdit}
                  value={settings.max_ban_days}
                  onChange={num('max_ban_days')}
                />
                {fields.max_ban_days && (
                  <span className="field-error">{fields.max_ban_days}</span>
                )}
              </label>
            </div>
            <p className="hint">
              Repeat offenders get twice the previous ban, up to the longest
              ban.
            </p>
            <fieldset>
              <legend>Automatic bans for abuse</legend>
              <label className="inline">
                <input
                  type="checkbox"
                  disabled={!canEdit}
                  checked={settings.abuse.enabled}
                  onChange={(e) =>
                    setSettings({
                      ...settings,
                      abuse: { ...settings.abuse, enabled: e.target.checked },
                    })
                  }
                />
                Ban addresses that keep misbehaving on your real hosts
              </label>
              <p className="hint">
                Works whether or not the honeypot is on. An address is banned on
                every host (for the ban lengths above) when, within the window,
                it gets at least this many of any one kind. 0 turns a kind off.
                Your local network and the never-block list are never banned.
              </p>
              <div className="actions">
                {(
                  [
                    ['rate_limited', 'Rate-limited (429)'],
                    ['blocked', 'Blocked by access rules'],
                    ['not_found', 'Not found (404)'],
                    ['window_minutes', 'Within (minutes)'],
                  ] as const
                ).map(([k, label]) => (
                  <label key={k}>
                    {label}
                    <input
                      type="number"
                      min={0}
                      className="small-num"
                      disabled={!canEdit || !settings.abuse.enabled}
                      value={settings.abuse[k]}
                      onChange={(e) =>
                        setSettings({
                          ...settings,
                          abuse: {
                            ...settings.abuse,
                            [k]: Number(e.target.value),
                          },
                        })
                      }
                    />
                    {fields[`abuse.${k}`] && (
                      <span className="field-error">
                        {fields[`abuse.${k}`]}
                      </span>
                    )}
                  </label>
                ))}
              </div>
              {fields['abuse.enabled'] && (
                <span className="field-error">{fields['abuse.enabled']}</span>
              )}
            </fieldset>
            {canEdit && (
              <div className="actions">
                <button>Save</button>
              </div>
            )}
          </form>
        )}
      </section>

      <section className="card">
        <h1>Trap paths</h1>
        <p className="hint">
          Paths scanners probe. A request for one, on any host, goes to the
          honeypot. Use * as a wildcard. If a host really serves one of these
          paths, add it to that host’s exceptions (host editor → Advanced).
        </p>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Path</th>
                <th className="num">Points</th>
                <th>On</th>
                {canEdit && <th aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {traps.map((t) => (
                <tr key={t.id} className={t.enabled ? '' : 'disabled'}>
                  <td className="mono">{t.pattern}</td>
                  <td className="num">
                    {canEdit ? (
                      <input
                        type="number"
                        min={0}
                        className="small-num"
                        defaultValue={t.score}
                        onBlur={(e) =>
                          Number(e.target.value) !== t.score &&
                          run(
                            () =>
                              api.saveTrap({
                                ...t,
                                score: Number(e.target.value),
                              }),
                            'Saved.',
                            true,
                          )
                        }
                      />
                    ) : (
                      t.score
                    )}
                  </td>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`Trap ${t.pattern} on`}
                      disabled={!canEdit}
                      checked={t.enabled}
                      onChange={() =>
                        run(
                          () => api.saveTrap({ ...t, enabled: !t.enabled }),
                          'Saved.',
                          true,
                        )
                      }
                    />
                  </td>
                  {canEdit && (
                    <td>
                      <button
                        className="link danger"
                        onClick={() =>
                          run(() => api.deleteTrap(t.id), 'Removed.', true)
                        }
                      >
                        Remove
                      </button>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {canEdit && (
          <form
            className="actions"
            onSubmit={(e) => {
              e.preventDefault()
              void run(
                () =>
                  api.saveTrap({
                    id: 0,
                    pattern: newTrap.pattern,
                    score: newTrap.score,
                    enabled: true,
                  }),
                'Added. Review and apply to send it to Caddy.',
                true,
              ).then(() => setNewTrap({ pattern: '', score: 10 }))
            }}
          >
            <input
              className="mono grow"
              placeholder="/backup.zip or /admin/*"
              required
              value={newTrap.pattern}
              onChange={(e) =>
                setNewTrap({ ...newTrap, pattern: e.target.value })
              }
            />
            <input
              type="number"
              className="small-num"
              aria-label="Points"
              value={newTrap.score}
              onChange={(e) =>
                setNewTrap({ ...newTrap, score: Number(e.target.value) })
              }
            />
            <button>Add trap</button>
            {fields.pattern && (
              <span className="field-error">{fields.pattern}</span>
            )}
          </form>
        )}
      </section>

      <section className="card">
        <div className="toolbar">
          <h1>Bans</h1>
          <label className="inline">
            <input
              type="checkbox"
              checked={showAll}
              onChange={(e) => setShowAll(e.target.checked)}
            />
            Include ended bans
          </label>
          <a className="button secondary" href="/api/bans/export?format=csv">
            Export CSV
          </a>
          <a className="button secondary" href="/api/bans/export?format=json">
            Export JSON
          </a>
        </div>
        {canEdit && (
          <form
            className="actions"
            onSubmit={(e) => {
              e.preventDefault()
              void run(
                () => api.addBan(ban.cidr, ban.reason, ban.days),
                `Banned ${ban.cidr}.`,
              ).then(() => setBan({ cidr: '', reason: '', days: 7 }))
            }}
          >
            <input
              className="mono"
              placeholder="203.0.113.7 or 203.0.113.0/24"
              required
              value={ban.cidr}
              onChange={(e) => setBan({ ...ban, cidr: e.target.value })}
            />
            <input
              className="grow"
              placeholder="Reason"
              value={ban.reason}
              onChange={(e) => setBan({ ...ban, reason: e.target.value })}
            />
            <label className="inline">
              for
              <input
                type="number"
                min={0}
                className="small-num"
                value={ban.days}
                onChange={(e) =>
                  setBan({ ...ban, days: Number(e.target.value) })
                }
              />
              days (0 = until lifted)
            </label>
            <button>Ban</button>
          </form>
        )}
        {bans.length === 0 ? (
          <p className="hint">No {showAll ? '' : 'active '}bans.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Address</th>
                  <th>Why</th>
                  <th>Since</th>
                  <th>Until</th>
                  {canEdit && <th aria-label="Actions" />}
                </tr>
              </thead>
              <tbody>
                {bans.map((b) => (
                  <tr key={b.id} className={b.active ? '' : 'disabled'}>
                    <td className="mono">{b.cidr}</td>
                    <td>
                      {b.reason || '—'}
                      <div className="hint">
                        {b.source}
                        {b.created_by &&
                          b.created_by !== b.source &&
                          ` · ${b.created_by}`}
                      </div>
                    </td>
                    <td>{new Date(b.created_at).toLocaleString()}</td>
                    <td>
                      {b.removed_at
                        ? `Lifted ${new Date(b.removed_at).toLocaleString()}`
                        : b.expires_at
                          ? new Date(b.expires_at).toLocaleString()
                          : 'Until lifted'}
                    </td>
                    {canEdit && (
                      <td>
                        {b.active && (
                          <button
                            className="link"
                            onClick={() =>
                              run(
                                () => api.removeBan(b.id),
                                `Lifted the ban on ${b.cidr}.`,
                              )
                            }
                          >
                            Lift
                          </button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {isAdmin && <CrowdSecCard onChanged={onChanged} />}

      {isAdmin && <UniFiCard />}

      <section className="card">
        <div className="toolbar">
          <h1>Activity</h1>
          <div className="segmented" role="group" aria-label="Time range">
            {['24h', '7d', '30d'].map((r) => (
              <button
                key={r}
                className={range === r ? '' : 'secondary'}
                onClick={() => setRange(r)}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
        {activity && (
          <>
            <div className="top-grid">
              <Mini title="Top paths" rows={activity.path} />
              <Mini title="Top sources" rows={activity.ip} />
              <Mini title="User agents" rows={activity.ua} mono={false} />
              <Mini title="Hosts asked for" rows={activity.host} />
            </div>
            <h2>Recent attempts</h2>
            {activity.recent.length === 0 ? (
              <p className="hint">No honeypot hits yet.</p>
            ) : (
              <div className="table-wrap">
                <table className="hits">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Source</th>
                      <th>Request</th>
                      <th>User agent</th>
                    </tr>
                  </thead>
                  <tbody>
                    {activity.recent.map((h) => (
                      <tr key={h.id}>
                        <td>{new Date(h.ts).toLocaleString()}</td>
                        <td className="mono">
                          {h.client_ip}{' '}
                          {h.country && (
                            <span className="hint">{h.country}</span>
                          )}
                        </td>
                        <td className="mono req-cell">
                          {h.method} {h.host}
                          {h.path}
                          <div className="hint">
                            {h.reason.startsWith('trap')
                              ? 'trap path'
                              : 'unknown host'}
                          </div>
                        </td>
                        <td className="req-cell">{h.user_agent || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </section>
    </div>
  )
}
