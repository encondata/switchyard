import { useEffect, useState, type FormEvent } from 'react'
import {
  api,
  ApiError,
  message,
  newHost,
  type CertStatus,
  type Host,
  type HostView,
  type Upstream,
} from './api'

const typeLabel = { proxy: 'Proxy', redirect: 'Redirect', '404': '404' }
const tlsLabel = { auto: 'Automatic', internal: 'Internal CA', off: 'Off' }

function CertBadge({ c }: { c: CertStatus }) {
  if (c.state === 'not_needed') return null
  const label = {
    valid: 'Cert OK',
    expiring: 'Expiring',
    expired: 'Expired',
    pending: 'No cert yet',
  }[c.state]
  const title = c.not_after
    ? `${c.issuer ?? ''} — expires ${new Date(c.not_after).toLocaleString()}`
    : 'Caddy hasn’t stored a certificate for this name yet. Apply the config and send a request.'
  return (
    <span className={`badge cert-${c.state}`} title={title}>
      {label}
    </span>
  )
}

function target(h: HostView): string {
  if (h.type === 'proxy')
    return h.upstreams
      .map((u) => `${u.scheme}://${u.host}:${u.port}`)
      .join(', ')
  if (h.type === 'redirect') return `→ ${h.redirect_to} (${h.redirect_code})`
  return 'Not found page'
}

export function HostList({
  canEdit,
  onChanged,
}: {
  canEdit: boolean
  onChanged: () => void
}) {
  const [hosts, setHosts] = useState<HostView[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [filter, setFilter] = useState('')

  function load() {
    api
      .hosts()
      .then(setHosts)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function toggle(h: HostView) {
    try {
      await api.saveHost({ ...h, enabled: !h.enabled })
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  async function remove(h: HostView) {
    if (!confirm(`Delete the host for ${h.domains.join(', ')}?`)) return
    try {
      await api.deleteHost(h.id)
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  const shown = (hosts ?? []).filter((h) =>
    h.domains.some((d) => d.includes(filter.trim().toLowerCase())),
  )

  return (
    <section className="card">
      <div className="toolbar">
        <h1>Hosts</h1>
        <input
          className="search"
          placeholder="Filter by domain"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
        />
        {canEdit && (
          <a className="button" href="#/hosts/new">
            Add host
          </a>
        )}
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!hosts && !error && <p>Loading…</p>}
      {hosts && hosts.length === 0 && (
        <div className="empty">
          <p>No hosts yet.</p>
          {canEdit && (
            <p className="hint">
              Add a proxy host, then review and apply the change to send it to
              Caddy.
            </p>
          )}
        </div>
      )}
      {shown.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Domains</th>
                <th>Type</th>
                <th>Target</th>
                <th>TLS</th>
                <th>Status</th>
                {canEdit && <th aria-label="Actions" />}
              </tr>
            </thead>
            <tbody>
              {shown.map((h) => (
                <tr key={h.id} className={h.enabled ? '' : 'disabled'}>
                  <td>
                    {h.domains.map((d, i) => (
                      <div key={d}>
                        {canEdit ? <a href={`#/hosts/${h.id}`}>{d}</a> : d}{' '}
                        {h.enabled && h.certs[i] && (
                          <CertBadge c={h.certs[i]} />
                        )}
                      </div>
                    ))}
                  </td>
                  <td>{typeLabel[h.type]}</td>
                  <td className="mono">{target(h)}</td>
                  <td>
                    {tlsLabel[h.tls_mode]}
                    {h.tls_mode !== 'off' && h.force_https && (
                      <div className="hint">Forces HTTPS</div>
                    )}
                  </td>
                  <td>
                    {canEdit ? (
                      <label className="switch">
                        <input
                          type="checkbox"
                          checked={h.enabled}
                          onChange={() => toggle(h)}
                        />
                        {h.enabled ? 'Enabled' : 'Disabled'}
                      </label>
                    ) : h.enabled ? (
                      'Enabled'
                    ) : (
                      'Disabled'
                    )}
                  </td>
                  {canEdit && (
                    <td>
                      <div className="row-actions">
                        <a href={`#/hosts/${h.id}`}>Edit</a>
                        <button
                          className="link danger"
                          onClick={() => remove(h)}
                        >
                          Delete
                        </button>
                      </div>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}

function FieldError({ msg }: { msg?: string }) {
  return msg ? <span className="field-error">{msg}</span> : null
}

export function HostEditor({
  id,
  onSaved,
}: {
  id: number | null
  onSaved: () => void
}) {
  const [host, setHost] = useState<Host | null>(id ? null : newHost())
  const [domains, setDomains] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    if (!id) return
    api
      .host(id)
      .then((h) => {
        setHost(h)
        setDomains(h.domains.join('\n'))
      })
      .catch((err: unknown) => setError(message(err)))
  }, [id])

  if (!host) return <p>{error ?? 'Loading…'}</p>

  const set = (patch: Partial<Host>) => setHost({ ...host, ...patch })
  const setUpstream = (i: number, patch: Partial<Upstream>) =>
    set({
      upstreams: host.upstreams.map((u, j) =>
        i === j ? { ...u, ...patch } : u,
      ),
    })

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (!host) return
    setBusy(true)
    setError(null)
    setFields({})
    try {
      await api.saveHost({
        ...host,
        domains: domains.split(/[\s,]+/).filter(Boolean),
      })
      onSaved()
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(false)
    }
  }

  const tls = host.tls_mode !== 'off'

  return (
    <form className="card" onSubmit={submit}>
      <h1>{id ? 'Edit host' : 'Add host'}</h1>

      <fieldset>
        <legend>Type</legend>
        <div className="segmented">
          {(['proxy', 'redirect', '404'] as const).map((t) => (
            <label key={t}>
              <input
                type="radio"
                name="type"
                checked={host.type === t}
                onChange={() => set({ type: t })}
              />
              {
                {
                  proxy: 'Proxy to a backend',
                  redirect: 'Redirect',
                  '404': 'Not found (404)',
                }[t]
              }
            </label>
          ))}
        </div>
      </fieldset>

      <label>
        Domains <span className="hint">(one per line)</span>
        <textarea
          rows={3}
          required
          value={domains}
          placeholder="app.example.com"
          onChange={(e) => setDomains(e.target.value)}
        />
        <FieldError msg={fields.domains} />
        <span className="hint">
          Tip: names ending in <code>.localhost</code> reach this computer
          without any DNS setup.
        </span>
      </label>

      {host.type === 'proxy' && (
        <fieldset>
          <legend>Upstreams</legend>
          {host.upstreams.map((u, i) => (
            <div className="upstream" key={i}>
              <select
                aria-label="Scheme"
                value={u.scheme}
                onChange={(e) =>
                  setUpstream(i, {
                    scheme: e.target.value as Upstream['scheme'],
                  })
                }
              >
                <option value="http">http://</option>
                <option value="https">https://</option>
              </select>
              <input
                aria-label="Host or IP"
                placeholder="host or IP"
                required
                value={u.host}
                onChange={(e) => setUpstream(i, { host: e.target.value })}
              />
              <input
                aria-label="Port"
                type="number"
                min={1}
                max={65535}
                required
                value={u.port}
                onChange={(e) =>
                  setUpstream(i, { port: Number(e.target.value) })
                }
              />
              {u.scheme === 'https' && (
                <label className="inline">
                  <input
                    type="checkbox"
                    checked={u.skip_tls_verify}
                    onChange={(e) =>
                      setUpstream(i, { skip_tls_verify: e.target.checked })
                    }
                  />
                  Skip TLS verify
                </label>
              )}
              {host.upstreams.length > 1 && (
                <button
                  type="button"
                  className="link danger"
                  onClick={() =>
                    set({ upstreams: host.upstreams.filter((_, j) => j !== i) })
                  }
                >
                  Remove
                </button>
              )}
            </div>
          ))}
          {host.upstreams.some((u) => u.skip_tls_verify) && (
            <p className="notice">
              Skipping TLS verification means Caddy will accept any certificate
              from the backend. Only use it for backends on a network you trust.
            </p>
          )}
          <FieldError msg={fields.upstreams} />
          <div className="actions">
            <button
              type="button"
              className="secondary"
              onClick={() =>
                set({
                  upstreams: [
                    ...host.upstreams,
                    {
                      scheme: 'http',
                      host: '',
                      port: 80,
                      skip_tls_verify: false,
                    },
                  ],
                })
              }
            >
              Add upstream
            </button>
            {host.upstreams.length > 1 && (
              <label className="inline">
                Load balancing
                <select
                  value={host.load_balancing}
                  onChange={(e) =>
                    set({
                      load_balancing: e.target.value as Host['load_balancing'],
                    })
                  }
                >
                  <option value="round_robin">Round robin</option>
                  <option value="first">First available</option>
                </select>
              </label>
            )}
          </div>
          <label className="inline">
            <input
              type="checkbox"
              checked={host.compression}
              onChange={(e) => set({ compression: e.target.checked })}
            />
            Compress responses (gzip, zstd)
          </label>
        </fieldset>
      )}

      {host.type === 'redirect' && (
        <fieldset>
          <legend>Redirect</legend>
          <label>
            Redirect to
            <input
              type="url"
              required
              placeholder="https://new.example.com"
              value={host.redirect_to}
              onChange={(e) => set({ redirect_to: e.target.value })}
            />
            <FieldError msg={fields.redirect_to} />
          </label>
          <div className="actions">
            <label className="inline">
              Status
              <select
                value={host.redirect_code}
                onChange={(e) => set({ redirect_code: Number(e.target.value) })}
              >
                <option value={301}>301 Moved permanently</option>
                <option value={302}>302 Found</option>
                <option value={307}>307 Temporary redirect</option>
                <option value={308}>308 Permanent redirect</option>
              </select>
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={host.preserve_path}
                onChange={(e) => set({ preserve_path: e.target.checked })}
              />
              Keep the path and query
            </label>
          </div>
        </fieldset>
      )}

      <fieldset>
        <legend>HTTPS</legend>
        <label>
          Certificate
          <select
            value={host.tls_mode}
            onChange={(e) =>
              set({ tls_mode: e.target.value as Host['tls_mode'] })
            }
          >
            <option value="auto">
              Automatic (Let’s Encrypt) — the domain must point at this server
            </option>
            <option value="internal">
              Internal CA — for LAN-only names; browsers will warn
            </option>
            <option value="off">Off — plain HTTP on port 80 only</option>
          </select>
        </label>
        {tls && (
          <div className="actions">
            <label className="inline">
              <input
                type="checkbox"
                checked={host.force_https}
                onChange={(e) => set({ force_https: e.target.checked })}
              />
              Redirect HTTP to HTTPS
            </label>
            <label className="inline">
              <input
                type="checkbox"
                checked={host.hsts}
                onChange={(e) => set({ hsts: e.target.checked })}
              />
              HSTS (browsers will insist on HTTPS for a year)
            </label>
          </div>
        )}
      </fieldset>

      <label>
        Notes
        <textarea
          rows={2}
          value={host.notes}
          onChange={(e) => set({ notes: e.target.value })}
        />
      </label>

      <label className="inline">
        <input
          type="checkbox"
          checked={host.enabled}
          onChange={(e) => set({ enabled: e.target.checked })}
        />
        Enabled
      </label>

      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        <button disabled={busy}>{busy ? 'Saving…' : 'Save'}</button>
        <a className="button secondary" href="#/hosts">
          Cancel
        </a>
      </div>
      <p className="hint">
        Saving stores the host. Caddy only changes when you review and apply.
      </p>
    </form>
  )
}
