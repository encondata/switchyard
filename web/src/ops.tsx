import { useEffect, useState } from 'react'
import { api, message, type CertRow, type Health } from './api'

function bytes(n: number): string {
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i++
  }
  return `${v.toFixed(v < 10 ? 1 : 0)} ${units[i]}`
}

const stateLabel = {
  valid: 'OK',
  expiring: 'Expiring',
  expired: 'Expired',
  pending: 'No cert yet',
  not_needed: '—',
}

const modeLabel = {
  auto: 'Let’s Encrypt (HTTP)',
  dns: 'Let’s Encrypt (DNS)',
  internal: 'Internal CA',
  off: 'Off',
}

export function Certificates({ canEdit }: { canEdit: boolean }) {
  const [rows, setRows] = useState<CertRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  function load() {
    api
      .certificates()
      .then(setRows)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function retry() {
    setBusy(true)
    setError(null)
    setInfo(null)
    try {
      await api.retryCerts()
      setInfo(
        'Caddy reloaded its config and is trying failed certificates again. Refresh in a minute.',
      )
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <section className="card">
      <div className="toolbar">
        <h1>Certificates</h1>
        <button className="secondary" onClick={load}>
          Refresh
        </button>
        {canEdit && (
          <button onClick={retry} disabled={busy}>
            {busy ? 'Retrying…' : 'Retry now'}
          </button>
        )}
      </div>
      <p className="hint">
        Caddy gets and renews certificates by itself. This page shows what it
        has stored and, if it failed, the error it reported. Expiry alerts start
        14 days before a certificate expires, once Caddy’s normal renewal time
        has passed.
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
      {rows?.length === 0 && <p>No enabled hosts use HTTPS yet.</p>}
      {rows && rows.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Issued by</th>
                <th>Status</th>
                <th>Expires</th>
                <th>Last error</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.domain}>
                  <td>
                    <a href={`#/hosts/${r.host_id}`}>{r.domain}</a>
                  </td>
                  <td>
                    {r.issuer ?? <span className="hint">—</span>}
                    <div className="hint">{modeLabel[r.tls_mode]}</div>
                  </td>
                  <td>
                    <span className={`badge cert-${r.state}`}>
                      {stateLabel[r.state]}
                    </span>
                  </td>
                  <td>
                    {r.not_after ? new Date(r.not_after).toLocaleString() : '—'}
                  </td>
                  <td className="error-cell">
                    {r.last_error ? (
                      <>
                        <span className="bad">{r.last_error.message}</span>
                        <div className="hint">
                          {new Date(r.last_error.at).toLocaleString()}
                        </div>
                      </>
                    ) : (
                      <span className="hint">—</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

export function HealthPage({ isAdmin }: { isAdmin: boolean }) {
  const [h, setH] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [restoreMsg, setRestoreMsg] = useState<string | null>(null)

  useEffect(() => {
    api
      .health()
      .then(setH)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  async function checkNow() {
    setBusy(true)
    try {
      setH(await api.checkNow())
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  async function restore(file: File | undefined) {
    if (!file) return
    if (
      !confirm(
        `Restore “${file.name}”? CPM replaces its database with this backup and restarts. The current database is kept next to it as a copy.`,
      )
    )
      return
    setRestoreMsg(null)
    try {
      setRestoreMsg(await api.restore(file))
      setTimeout(() => location.reload(), 6000)
    } catch (err) {
      setRestoreMsg(message(err))
    }
  }

  const m = h?.monitor
  return (
    <div className="stack">
      <section className="card">
        <div className="toolbar">
          <h1>Health</h1>
          <button className="secondary" onClick={checkNow} disabled={busy}>
            {busy ? 'Checking…' : 'Check now'}
          </button>
        </div>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {!h && !error && <p>Loading…</p>}
        {h && m && (
          <dl>
            <dt>CPM version</dt>
            <dd>{h.version}</dd>
            <dt>Caddy</dt>
            <dd>
              {m.caddy_reachable ? (
                <span className="ok">Reachable</span>
              ) : (
                <span className="bad">
                  Not reachable{m.caddy_error ? `: ${m.caddy_error}` : ''}
                </span>
              )}
            </dd>
            <dt>Running config</dt>
            <dd>
              {m.drift ? (
                <span className="bad">
                  Differs from what CPM applied last —{' '}
                  <a href="#/changes">review and apply</a>
                </span>
              ) : (
                <span className="ok">Matches CPM</span>
              )}
            </dd>
            <dt>Last apply</dt>
            <dd>
              {m.last_apply ? (
                <>
                  Version {m.last_apply.n},{' '}
                  {new Date(m.last_apply.applied_at).toLocaleString()} by{' '}
                  {m.last_apply.applied_by}:{' '}
                  {m.last_apply.result === 'ok' ? (
                    <span className="ok">applied</span>
                  ) : (
                    <span className="bad">rejected — {m.last_apply.error}</span>
                  )}
                </>
              ) : (
                'Nothing applied yet'
              )}
            </dd>
            <dt>Caddy logs on disk</dt>
            <dd>{bytes(m.log_bytes)}</dd>
            <dt>Database</dt>
            <dd>{bytes(h.db_bytes)}</dd>
            <dt>Secret key</dt>
            <dd>
              {h.secrets_ready ? (
                <span className="ok">Set</span>
              ) : (
                <span className="bad">
                  CPM_SECRET_KEY not set (needed for DNS providers)
                </span>
              )}
            </dd>
            <dt>GeoIP database</dt>
            <dd className="hint">Not configured (country rules, phase 2)</dd>
            <dt>Last check</dt>
            <dd>
              {m.checked_at && !m.checked_at.startsWith('0001')
                ? new Date(m.checked_at).toLocaleString()
                : 'Not yet'}{' '}
              <span className="hint">(every minute)</span>
            </dd>
          </dl>
        )}
      </section>

      <section className="card">
        <h1>Alerts</h1>
        {h?.alerts.length === 0 && <p className="ok">No open alerts.</p>}
        {h && h.alerts.length > 0 && (
          <ul className="alert-list">
            {h.alerts.map((a) => (
              <li key={a.id}>
                <strong>{a.message}</strong>
                <div className="hint">
                  Since {new Date(a.created_at).toLocaleString()} · last seen{' '}
                  {new Date(a.last_seen_at).toLocaleString()}
                </div>
              </li>
            ))}
          </ul>
        )}
        <p className="hint">
          Alerts clear themselves once the problem is gone. Email alerts come
          later.
        </p>
      </section>

      {isAdmin && (
        <section className="card">
          <h1>Backup and restore</h1>
          <p className="hint">
            The backup is CPM’s whole database: hosts, folders, policies, users,
            history and DNS tokens (still encrypted, so restoring needs the same
            CPM_SECRET_KEY). Caddy’s certificates live in Caddy’s own volume.
          </p>
          <div className="actions">
            <a className="button" href="/api/backup">
              Download backup
            </a>
            <label className="button secondary file-button">
              Restore from file…
              <input
                type="file"
                accept=".db,application/vnd.sqlite3"
                onChange={(e) => restore(e.target.files?.[0])}
              />
            </label>
          </div>
          {restoreMsg && <p className="notice">{restoreMsg}</p>}
        </section>
      )}
    </div>
  )
}
