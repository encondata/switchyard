import { useEffect, useState, type FormEvent } from 'react'
import {
  CircleCheck,
  RefreshCw,
  ShieldAlert,
  TriangleAlert,
} from 'lucide-react'
import {
  api,
  ApiError,
  message,
  type UniFiCheck,
  type UniFiSettings,
  type UniFiStatus,
} from './api'

/** Keep the ban list in a UniFi firewall, so bans are dropped at the gateway. */
export function UniFiCard() {
  const [u, setU] = useState<UniFiSettings | null>(null)
  const [status, setStatus] = useState<UniFiStatus | null>(null)
  const [key, setKey] = useState('')
  const [check, setCheck] = useState<UniFiCheck | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    api
      .unifi()
      .then((v) => {
        setU(v.settings)
        setStatus(v.status ?? null)
      })
      .catch((err: unknown) => setError(message(err)))
  }, [])

  async function doCheck(trust = '') {
    if (!u) return
    setBusy('check')
    setError(null)
    try {
      const r = await api.checkUniFi(u.url, key, trust || u.cert_sha256)
      setCheck(r)
      if (!r.needs_trust && !r.error) {
        // Trusted: remember the pin (empty when the certificate is valid).
        const pin = r.cert_sha256
        const only = r.sites.length === 1 ? r.sites[0] : null
        setU({
          ...u,
          cert_sha256: pin,
          site_id:
            u.site_id && r.sites.some((s) => s.id === u.site_id)
              ? u.site_id
              : (only?.id ?? ''),
          site_name:
            u.site_id && r.sites.some((s) => s.id === u.site_id)
              ? u.site_name
              : (only?.name ?? ''),
        })
      }
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(null)
    }
  }

  async function save(e: FormEvent) {
    e.preventDefault()
    if (!u) return
    setBusy('save')
    setError(null)
    setFields({})
    setSaved(false)
    try {
      const v = await api.saveUniFi({ ...u, api_key: key })
      setU(v.settings)
      setStatus(v.status ?? null)
      setKey('')
      setSaved(true)
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(null)
    }
  }

  async function syncNow() {
    setBusy('sync')
    try {
      setStatus(await api.syncUniFi())
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(null)
    }
  }

  if (!u) return null
  const v4 = status?.lists?.find((l) => l.type === 'IPv4')
  const v6 = status?.lists?.find((l) => l.type === 'IPv6')
  const blocking = (l?: { policies: { enabled: boolean; action: string }[] }) =>
    !!l?.policies.some(
      (p) => p.enabled && (p.action === 'BLOCK' || p.action === 'REJECT'),
    )

  return (
    <section className="card">
      <h1>UniFi firewall (optional)</h1>
      <p className="hint">
        Keep the ban list in your UniFi gateway’s firewall, so banned addresses
        are dropped before they reach Caddy. Switchyard keeps an IP list called
        “{u.list_name} (IPv4)” up to date (and an IPv6 one once there’s an IPv6
        ban); a firewall policy on the console blocks it. Needs UniFi Network 10
        or newer.
      </p>
      <form className="folder-form" onSubmit={save}>
        <div className="actions">
          <label className="grow">
            Console address
            <input
              placeholder="https://192.168.1.1"
              value={u.url}
              onChange={(e) => (
                setU({ ...u, url: e.target.value }),
                setCheck(null)
              )}
            />
            {fields.url && <span className="field-error">{fields.url}</span>}
          </label>
          <label className="grow">
            API key
            <input
              type="password"
              autoComplete="off"
              placeholder={
                u.key_set
                  ? 'Saved (leave empty to keep it)'
                  : 'From the console'
              }
              value={key}
              onChange={(e) => setKey(e.target.value)}
            />
            {fields.api_key && (
              <span className="field-error">{fields.api_key}</span>
            )}
          </label>
        </div>
        <p className="hint">
          Make the key on the console: Settings → Control Plane → Integrations →
          Create API key. The key acts as the admin who makes it, so use an
          admin with Network access.
        </p>
        <div className="actions">
          <button
            type="button"
            className="secondary"
            disabled={!u.url || busy !== null}
            onClick={() => void doCheck()}
          >
            {busy === 'check' ? 'Checking…' : 'Check connection'}
          </button>
          {u.cert_sha256 && !check && (
            <span className="hint">
              Trusted certificate {fingerprintShort(u.cert_sha256)}
            </span>
          )}
        </div>

        {check?.error && <p className="error">{check.error}</p>}
        {check?.needs_trust && check.cert && (
          <div className="notice trust">
            <p>
              <ShieldAlert size={16} aria-hidden="true" />{' '}
              {check.cert_changed ? (
                <strong>
                  The console’s certificate has changed since you trusted it.
                  Only trust the new one if you know why (for example, you
                  replaced it).
                </strong>
              ) : (
                <>
                  The console uses its own certificate (UniFi consoles do out of
                  the box), so it can’t be checked the usual way. Trust it if
                  the fingerprint matches the one your browser shows for{' '}
                  <span className="mono">{u.url}</span>; Switchyard will then
                  only talk to a console with this exact certificate.
                </>
              )}
            </p>
            <dl>
              <dt>Issued to</dt>
              <dd>{check.cert.subject || '—'}</dd>
              <dt>Expires</dt>
              <dd>{new Date(check.cert.expires).toLocaleDateString()}</dd>
              <dt>SHA-256</dt>
              <dd className="mono fingerprint">{check.fingerprint}</dd>
            </dl>
            <div className="actions">
              <button
                type="button"
                onClick={() => void doCheck(check.cert!.sha256)}
              >
                Trust this certificate
              </button>
            </div>
          </div>
        )}
        {check && !check.needs_trust && !check.error && (
          <p className="success">
            <CircleCheck size={16} aria-hidden="true" /> Connected
            {check.cert?.valid
              ? ' (valid certificate)'
              : ' (trusted certificate)'}
            .{' '}
            {check.sites.length > 1 ? `${check.sites.length} sites found.` : ''}
          </p>
        )}

        {(check?.sites.length || u.site_id) && (
          <div className="actions">
            <label className="grow">
              Site
              {check && check.sites.length > 0 ? (
                <select
                  value={u.site_id}
                  onChange={(e) => {
                    const s = check.sites.find((x) => x.id === e.target.value)
                    setU({
                      ...u,
                      site_id: e.target.value,
                      site_name: s?.name ?? '',
                    })
                  }}
                >
                  <option value="">Choose…</option>
                  {check.sites.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.name}
                    </option>
                  ))}
                </select>
              ) : (
                <input value={u.site_name || u.site_id} disabled />
              )}
              {fields.site_id && (
                <span className="field-error">{fields.site_id}</span>
              )}
            </label>
            <label className="grow">
              List name
              <input
                value={u.list_name}
                onChange={(e) => setU({ ...u, list_name: e.target.value })}
              />
            </label>
          </div>
        )}
        <label className="inline">
          <input
            type="checkbox"
            checked={u.enabled}
            onChange={(e) => setU({ ...u, enabled: e.target.checked })}
          />
          Keep the ban list in this console’s firewall
        </label>
        {error && <p className="error">{error}</p>}
        {saved && !error && <p className="success">Saved.</p>}
        <div className="actions">
          <button disabled={busy !== null}>
            {busy === 'save' ? 'Saving…' : 'Save'}
          </button>
          {u.enabled && (
            <button
              type="button"
              className="secondary"
              disabled={busy !== null}
              onClick={() => void syncNow()}
            >
              <RefreshCw size={15} aria-hidden="true" />{' '}
              {busy === 'sync' ? 'Syncing…' : 'Sync now'}
            </button>
          )}
        </div>
      </form>

      {u.enabled && status?.enabled && (
        <div className="unifi-status">
          <h2>Last sync</h2>
          {status.last_error ? (
            <p className="error">
              <TriangleAlert size={16} aria-hidden="true" /> {status.last_error}
            </p>
          ) : (
            <p>
              {status.last_sync
                ? new Date(status.last_sync).toLocaleString()
                : 'Not yet'}{' '}
              · {status.ipv4} IPv4 and {status.ipv6} IPv6 banned addresses sent.
              It syncs within seconds of a ban changing, and every 5 minutes.
            </p>
          )}
          {[v4, v6].filter(Boolean).map((l) => (
            <div key={l!.id} className={blocking(l) ? 'success' : 'notice'}>
              <strong>{l!.name}</strong>:{' '}
              {l!.policies.length === 0
                ? `no firewall policy uses this list yet, so nothing is blocked.${
                    l!.type === 'IPv6' && blocking(v4)
                      ? ' Add a Block policy for it on the console, like the IPv4 one.'
                      : ''
                  }`
                : l!.policies
                    .map(
                      (p) =>
                        `${p.name} (${p.enabled ? p.action.toLowerCase() : 'off'})`,
                    )
                    .join(', ')}
            </div>
          ))}
          {!blocking(v4) && !status.last_error && (
            <div className="hint">
              <p>
                <strong>One-time step on the console:</strong> in UniFi
                Network’s firewall (zone-based firewall policies), create a
                policy:
              </p>
              <ol className="steps">
                <li>
                  Name it, e.g. “Drop Switchyard bans”, with action Block.
                </li>
                <li>
                  Source: the External zone, matching the IP list “{u.list_name}{' '}
                  (IPv4)”.
                </li>
                <li>
                  Destination: the zone your port forwards to Switchyard land in
                  (usually Internal). Add the same policy for the Gateway zone
                  too if you also want them kept off the gateway itself.
                </li>
                <li>
                  Save, then click Sync now here: this card shows the policy
                  once it’s found.
                </li>
              </ol>
              {v6 && (
                <p>
                  Add a second policy the same way for “{u.list_name} (IPv6)”.
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  )
}

function fingerprintShort(hex: string) {
  const up = hex.toUpperCase()
  return `${up.slice(0, 2)}:${up.slice(2, 4)}…${up.slice(-4, -2)}:${up.slice(-2)}`
}
