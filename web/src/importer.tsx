import { useState, type FormEvent } from 'react'
import {
  api,
  message,
  type ImportPlan,
  type ImportResult,
  type MySQLConfig,
} from './api'

const tlsText = {
  auto: 'Let’s Encrypt',
  dns: 'DNS challenge',
  internal: 'Internal CA',
  off: 'HTTP only',
}

export function ImportPage({ onImported }: { onImported: () => void }) {
  const [source, setSource] = useState<'file' | 'mysql'>('file')
  const [mysql, setMysql] = useState<MySQLConfig>({
    host: '',
    port: 3306,
    user: 'npm',
    password: '',
    database: 'npm',
  })
  const [preview, setPreview] = useState<{
    plan_id: string
    plan: ImportPlan
  } | null>(null)
  const [result, setResult] = useState<ImportResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function run(fn: () => Promise<void>) {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  const fromFile = (file: File | undefined) =>
    file &&
    void run(async () => {
      setResult(null)
      setPreview(await api.importPreviewFile(file))
    })

  const fromMySQL = (e: FormEvent) => {
    e.preventDefault()
    void run(async () => {
      setResult(null)
      setPreview(await api.importPreviewMySQL(mysql))
    })
  }

  const plan = preview?.plan
  const toImport = plan?.hosts.filter((h) => !h.skip) ?? []

  return (
    <div className="stack">
      <section className="card">
        <h1>Import from Nginx Proxy Manager</h1>
        <p className="hint">
          CPM reads NPM’s database and shows what it will create. Nothing
          changes until you confirm. Imported hosts go into the “Imported”
          folder, <strong>disabled</strong>, so you can review each one before
          enabling it. NPM isn’t touched.
        </p>
        <div className="segmented">
          <label>
            <input
              type="radio"
              checked={source === 'file'}
              onChange={() => setSource('file')}
            />
            SQLite file (default NPM install)
          </label>
          <label>
            <input
              type="radio"
              checked={source === 'mysql'}
              onChange={() => setSource('mysql')}
            />
            MySQL / MariaDB
          </label>
        </div>
        {source === 'file' ? (
          <div className="stack-tight">
            <p className="hint">
              Copy <code>/data/database.sqlite</code> out of the NPM container,
              e.g. <code>docker cp npm:/data/database.sqlite .</code>
            </p>
            <label className="button secondary file-button">
              {busy ? 'Reading…' : 'Choose database.sqlite…'}
              <input
                type="file"
                accept=".sqlite,.db"
                onChange={(e) => fromFile(e.target.files?.[0])}
              />
            </label>
          </div>
        ) : (
          <form className="folder-form" onSubmit={fromMySQL}>
            <div className="actions">
              <label className="grow">
                Host
                <input
                  required
                  value={mysql.host}
                  onChange={(e) => setMysql({ ...mysql, host: e.target.value })}
                />
              </label>
              <label>
                Port
                <input
                  type="number"
                  value={mysql.port}
                  onChange={(e) =>
                    setMysql({ ...mysql, port: Number(e.target.value) })
                  }
                />
              </label>
            </div>
            <div className="actions">
              <label className="grow">
                User
                <input
                  required
                  value={mysql.user}
                  onChange={(e) => setMysql({ ...mysql, user: e.target.value })}
                />
              </label>
              <label className="grow">
                Password
                <input
                  type="password"
                  autoComplete="off"
                  value={mysql.password}
                  onChange={(e) =>
                    setMysql({ ...mysql, password: e.target.value })
                  }
                />
              </label>
              <label className="grow">
                Database
                <input
                  required
                  value={mysql.database}
                  onChange={(e) =>
                    setMysql({ ...mysql, database: e.target.value })
                  }
                />
              </label>
            </div>
            <div className="actions">
              <button disabled={busy}>
                {busy ? 'Reading…' : 'Preview import'}
              </button>
            </div>
            <p className="hint">
              CPM must be able to reach the database from its container. The
              password is used once and not stored.
            </p>
          </form>
        )}
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {result && (
          <p className="success" role="status">
            Imported {result.hosts_created} host(s) and{' '}
            {result.policies_created} access policy(ies) into the Imported
            folder, all disabled. Review them on the <a href="#/hosts">Hosts</a>{' '}
            page, enable them, then review and apply.
            {result.skipped.length > 0 &&
              ` Skipped: ${result.skipped.join('; ')}`}
          </p>
        )}
      </section>

      {plan && !result && (
        <section className="card">
          <div className="toolbar">
            <h1>Preview</h1>
            <button
              disabled={busy || toImport.length === 0}
              onClick={() =>
                run(async () => {
                  setResult(await api.importRun(preview.plan_id))
                  setPreview(null)
                  onImported()
                })
              }
            >
              Import {toImport.length} host(s)
            </button>
          </div>
          {plan.warnings.length > 0 && (
            <ul className="notice warn-list">
              {plan.warnings.map((w) => (
                <li key={w}>{w}</li>
              ))}
            </ul>
          )}
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>From NPM</th>
                  <th>Domains</th>
                  <th>Becomes</th>
                  <th>Notes</th>
                </tr>
              </thead>
              <tbody>
                {plan.hosts.map((h) => (
                  <tr key={h.source} className={h.skip ? 'disabled' : ''}>
                    <td className="mono">{h.source}</td>
                    <td>
                      {h.host.domains.map((d) => (
                        <div key={d}>{d}</div>
                      ))}
                    </td>
                    <td>
                      {h.host.type === 'proxy' &&
                        `Proxy → ${h.host.upstreams
                          .map((u) => `${u.scheme}://${u.host}:${u.port}`)
                          .join(', ')}`}
                      {h.host.type === 'redirect' &&
                        `Redirect → ${h.host.redirect_to} (${h.host.redirect_code})`}
                      {h.host.type === '404' && '404 page'}
                      <div className="hint">
                        {tlsText[h.host.tls_mode]}
                        {h.host.force_https && ', forces HTTPS'}
                        {h.policies.length > 0 && ` · ${h.policies.join(', ')}`}
                      </div>
                    </td>
                    <td>
                      {h.skip && <span className="bad">Skipped: {h.skip}</span>}
                      {h.warnings.map((w) => (
                        <div key={w} className="hint">
                          ⚠ {w}
                        </div>
                      ))}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {plan.policies.length > 0 && (
            <>
              <h2>Access lists → policies</h2>
              <ul>
                {plan.policies.map((p) => (
                  <li key={p.policy.name}>
                    <strong>{p.policy.name}</strong> (
                    {p.policy.mode === 'allow_only' ? 'allow only' : 'deny'}):{' '}
                    <span className="mono">{p.policy.rules.join(', ')}</span>
                  </li>
                ))}
              </ul>
            </>
          )}
          {plan.streams.length > 0 && (
            <>
              <h2>Streams (not imported)</h2>
              <ul>
                {plan.streams.map((s) => (
                  <li key={s.id} className="mono">
                    :{s.incoming_port} → {s.forward} ({s.protocols})
                    {!s.enabled && ' — disabled'}
                  </li>
                ))}
              </ul>
            </>
          )}
        </section>
      )}
    </div>
  )
}
