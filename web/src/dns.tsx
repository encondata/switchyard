import { useEffect, useState, type FormEvent } from 'react'
import {
  api,
  ApiError,
  message,
  type DNSProvider,
  type TokenCheck,
} from './api'

function ProviderForm({
  provider,
  onDone,
}: {
  provider: DNSProvider | null
  onDone: (changed: DNSProvider | null) => void
}) {
  const [name, setName] = useState(provider?.name ?? 'Cloudflare')
  const [token, setToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setFields({})
    try {
      onDone(await api.saveDNSProvider(provider?.id ?? 0, name, token))
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  return (
    <form className="folder-form" onSubmit={submit}>
      <h2>{provider ? `Edit “${provider.name}”` : 'Add Cloudflare'}</h2>
      <label>
        Name
        <input
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {fields.name && <span className="field-error">{fields.name}</span>}
      </label>
      <label>
        API token{' '}
        {provider && (
          <span className="hint">(leave empty to keep the current token)</span>
        )}
        <input
          type="password"
          autoComplete="off"
          required={!provider}
          className="mono"
          value={token}
          onChange={(e) => setToken(e.target.value)}
        />
        {fields.api_token && (
          <span className="field-error">{fields.api_token}</span>
        )}
      </label>
      <div className="notice">
        In Cloudflare: <strong>My Profile → API Tokens → Create Token</strong>,
        with these permissions, limited to the zones CPM should manage:
        <ul>
          <li>Zone → Zone → Read</li>
          <li>Zone → DNS → Edit</li>
        </ul>
        The token is encrypted in CPM’s database and handed to Caddy as a file;
        it never appears in the config, its history or diffs.
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        <button>Save</button>
        <button
          type="button"
          className="secondary"
          onClick={() => onDone(null)}
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

export function DNSPage({
  isAdmin,
  onChanged,
}: {
  isAdmin: boolean
  onChanged: () => void
}) {
  const [providers, setProviders] = useState<DNSProvider[] | null>(null)
  const [ready, setReady] = useState(true)
  const [editing, setEditing] = useState<DNSProvider | 'new' | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [checks, setChecks] = useState<
    Record<number, TokenCheck | { error: string } | 'checking'>
  >({})

  function load() {
    api
      .dnsProviders()
      .then((r) => {
        setProviders(r.providers)
        setReady(r.secrets_ready)
      })
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function check(id: number) {
    setChecks((c) => ({ ...c, [id]: 'checking' }))
    try {
      const r = await api.verifyDNSProvider(id)
      setChecks((c) => ({ ...c, [id]: r }))
    } catch (err) {
      setChecks((c) => ({ ...c, [id]: { error: message(err) } }))
    }
  }

  async function remove(p: DNSProvider) {
    if (!confirm(`Delete “${p.name}” and its stored token?`)) return
    setError(null)
    try {
      await api.deleteDNSProvider(p.id)
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  if (editing)
    return (
      <section className="card">
        <ProviderForm
          provider={editing === 'new' ? null : editing}
          onDone={(saved) => {
            setEditing(null)
            if (saved) {
              load()
              onChanged()
              void check(saved.id)
            }
          }}
        />
      </section>
    )

  return (
    <section className="card">
      <div className="toolbar">
        <h1>DNS providers</h1>
        {isAdmin && ready && (
          <button onClick={() => setEditing('new')}>Add Cloudflare</button>
        )}
      </div>
      <p className="hint">
        Hosts with the certificate set to <strong>DNS challenge</strong> prove
        domain ownership by adding a TXT record through your DNS provider. That
        works for wildcard domains and for names that aren’t reachable from the
        internet. Set a default provider on a folder, or choose one per host.
      </p>
      {!ready && (
        <p className="error">
          CPM_SECRET_KEY isn’t set, so tokens can’t be stored. Put{' '}
          <code>CPM_SECRET_KEY=$(openssl rand -base64 32)</code> in{' '}
          <code>.env</code> next to <code>compose.yaml</code> and restart CPM.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {providers?.length === 0 && ready && <p>No DNS providers yet.</p>}
      {providers && providers.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Used by</th>
                <th>Token check</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {providers.map((p) => {
                const c = checks[p.id]
                return (
                  <tr key={p.id}>
                    <td>
                      {p.name}
                      <div className="hint">Cloudflare</div>
                    </td>
                    <td>
                      {p.host_count} host(s), {p.folder_count} folder(s)
                    </td>
                    <td>
                      {c === undefined && <span className="hint">—</span>}
                      {c === 'checking' && 'Checking…'}
                      {c && c !== 'checking' && 'error' in c && (
                        <span className="bad">{c.error}</span>
                      )}
                      {c && c !== 'checking' && 'active' in c && (
                        <>
                          <span className={c.active ? 'ok' : 'bad'}>
                            Token {c.status || 'unknown'}
                          </span>
                          {c.zones.length > 0 && (
                            <div className="hint">
                              Zones: {c.zones.join(', ')}
                            </div>
                          )}
                          {c.zones_error && (
                            <div className="bad">{c.zones_error}</div>
                          )}
                        </>
                      )}
                    </td>
                    <td>
                      <div className="row-actions">
                        <button className="link" onClick={() => check(p.id)}>
                          Test token
                        </button>
                        {isAdmin && (
                          <>
                            <button
                              className="link"
                              onClick={() => setEditing(p)}
                            >
                              Edit
                            </button>
                            <button
                              className="link danger"
                              onClick={() => remove(p)}
                            >
                              Delete
                            </button>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
