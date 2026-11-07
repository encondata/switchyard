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

export function HoneypotPage({
  canEdit,
  onChanged,
}: {
  canEdit: boolean
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
