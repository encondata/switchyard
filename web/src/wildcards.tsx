import { useEffect, useState, type FormEvent } from 'react'
import { ShieldCheck } from 'lucide-react'
import {
  api,
  ApiError,
  message,
  type DNSProvider,
  type WildcardView,
} from './api'

const stateText: Record<string, string> = {
  valid: 'Valid',
  expiring: 'Expiring soon',
  expired: 'Expired',
  pending: 'Not issued yet',
  not_needed: '—',
}

/**
 * Shared wildcard certificates. One *.example.com certificate covers every
 * host one level under it, so those hosts never get a certificate of their
 * own and never show up in Certificate Transparency logs.
 */
export function WildcardCard({
  canEdit,
  onChanged,
}: {
  canEdit: boolean
  onChanged?: () => void
}) {
  const [list, setList] = useState<WildcardView[] | null>(null)
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [domain, setDomain] = useState('')
  const [provider, setProvider] = useState<number | ''>('')
  const [apex, setApex] = useState(true)
  const [open, setOpen] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [info, setInfo] = useState<string | null>(null)

  function load() {
    api
      .wildcards()
      .then(setList)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(() => {
    load()
    api
      .dnsProviders()
      .then((r) => {
        setProviders(r.providers)
        if (r.providers.length === 1) setProvider(r.providers[0].id)
      })
      .catch(() => undefined)
  }, [])

  async function add(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setFields({})
    setInfo(null)
    try {
      await api.saveWildcard({
        domain,
        dns_provider_id: Number(provider),
        include_apex: apex,
      })
      setDomain('')
      setInfo(
        'Added. Review and apply to obtain the certificate; covered hosts switch to it then.',
      )
      load()
      onChanged?.()
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  async function remove(w: WildcardView) {
    if (
      !confirm(
        `Remove the wildcard certificate for *.${w.domain}? The ${w.hosts.length} host(s) it covers will get certificates of their own (and appear in the public CT logs) after the next apply.`,
      )
    )
      return
    try {
      await api.deleteWildcard(w.id)
      load()
      onChanged?.()
    } catch (err) {
      setError(message(err))
    }
  }

  const name = (id: number) =>
    providers.find((p) => p.id === id)?.name ?? `#${id}`

  return (
    <section className="card">
      <h1>Wildcard certificates</h1>
      <p className="hint">
        Every certificate is published in public Certificate Transparency logs,
        and scanners watch them: a new host is probed within minutes of getting
        its certificate. One wildcard certificate (for{' '}
        <span className="mono">*.example.com</span>) covers every host one level
        under the domain, so new hosts never appear in the logs. Needs the
        domain’s DNS on a DNS provider (see <a href="#/dns">DNS</a>).
      </p>
      {error && <p className="error">{error}</p>}
      {info && <p className="success">{info}</p>}
      {list && list.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Certificate</th>
                <th>DNS provider</th>
                <th>Status</th>
                <th>Covers</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {list.map((w) => (
                <tr key={w.id}>
                  <td>
                    <span className="mono">*.{w.domain}</span>
                    {w.include_apex && (
                      <div className="hint mono">and {w.domain}</div>
                    )}
                  </td>
                  <td>{name(w.dns_provider_id)}</td>
                  <td>
                    <span className={`badge cert-${w.status.state}`}>
                      {stateText[w.status.state] ?? w.status.state}
                    </span>
                    {w.status.not_after && (
                      <div className="hint">
                        until{' '}
                        {new Date(w.status.not_after).toLocaleDateString()}
                      </div>
                    )}
                  </td>
                  <td>
                    {w.hosts.length === 0 ? (
                      <span className="hint">No hosts yet</span>
                    ) : (
                      <button
                        className="link"
                        onClick={() => setOpen(open === w.id ? null : w.id)}
                      >
                        {w.hosts.length} host name
                        {w.hosts.length === 1 ? '' : 's'}
                      </button>
                    )}
                    {open === w.id && (
                      <ul className="perm-list">
                        {w.hosts.map((h) => (
                          <li key={h.domain}>
                            <a href={`#/hosts/${h.id}`} className="mono">
                              {h.domain}
                            </a>
                          </li>
                        ))}
                      </ul>
                    )}
                  </td>
                  <td>
                    {canEdit && (
                      <button
                        className="link danger"
                        onClick={() => void remove(w)}
                      >
                        Remove
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {canEdit && (
        <form className="actions wildcard-form" onSubmit={add}>
          <label className="grow">
            Domain
            <span className="wildcard-input">
              <span className="mono hint">*.</span>
              <input
                required
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
              />
            </span>
            {fields.domain && (
              <span className="field-error">{fields.domain}</span>
            )}
          </label>
          <label>
            DNS provider
            <select
              required
              value={provider}
              onChange={(e) =>
                setProvider(e.target.value ? Number(e.target.value) : '')
              }
            >
              <option value="">Choose…</option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            {fields.dns_provider_id && (
              <span className="field-error">{fields.dns_provider_id}</span>
            )}
          </label>
          <label className="inline">
            <input
              type="checkbox"
              checked={apex}
              onChange={(e) => setApex(e.target.checked)}
            />
            Also cover the bare domain
          </label>
          <button disabled={providers.length === 0}>
            <ShieldCheck size={16} aria-hidden="true" /> Add wildcard
          </button>
          {providers.length === 0 && (
            <span className="hint">
              Add a DNS provider first, on the <a href="#/dns">DNS</a> page.
            </span>
          )}
        </form>
      )}
    </section>
  )
}
