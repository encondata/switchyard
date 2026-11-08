import { useEffect, useMemo, useState, type FormEvent } from 'react'
import { Check, Copy, KeyRound, Plus, Search } from 'lucide-react'
import {
  api,
  ApiError,
  message,
  type APIKey,
  type APIKeyInput,
  type APIOperation,
  type OpenAPIDoc,
} from './api'
import { PageHeader } from './shell'

const when = (t: string | null) => (t ? new Date(t).toLocaleString() : '—')

function keyState(k: APIKey): { label: string; cls: string } {
  if (k.revoked_at) return { label: 'Revoked', cls: 'cert-expired' }
  if (k.expires_at && new Date(k.expires_at) < new Date())
    return { label: 'Expired', cls: 'cert-expired' }
  return { label: 'Active', cls: 'cert-valid' }
}

function Method({ m }: { m: string }) {
  return <span className={`method method-${m.toLowerCase()}`}>{m}</span>
}

function CopyButton({
  text,
  label = 'Copy',
}: {
  text: string
  label?: string
}) {
  const [done, setDone] = useState(false)
  return (
    <button
      type="button"
      className="secondary small"
      onClick={() => {
        void navigator.clipboard.writeText(text).then(() => {
          setDone(true)
          setTimeout(() => setDone(false), 2000)
        })
      }}
    >
      {done ? (
        <Check size={14} aria-hidden="true" />
      ) : (
        <Copy size={14} aria-hidden="true" />
      )}
      {done ? 'Copied' : label}
    </button>
  )
}

/** Pick exactly which operations a key may call, grouped by area. */
function PermissionPicker({
  ops,
  value,
  onChange,
}: {
  ops: APIOperation[]
  value: Set<string>
  onChange: (v: Set<string>) => void
}) {
  const [q, setQ] = useState('')
  const areas = useMemo(() => {
    const m = new Map<string, APIOperation[]>()
    for (const o of ops) m.set(o.area, [...(m.get(o.area) ?? []), o])
    return [...m.entries()]
  }, [ops])
  const term = q.trim().toLowerCase()
  const match = (o: APIOperation) =>
    !term ||
    [o.id, o.path, o.summary, o.area].some((x) =>
      x.toLowerCase().includes(term),
    )
  const set = (ids: string[], on: boolean) => {
    const next = new Set(value)
    for (const id of ids) {
      if (on) next.add(id)
      else next.delete(id)
    }
    onChange(next)
  }

  return (
    <div className="picker">
      <div className="picker-tools">
        <label className="picker-search">
          <Search size={16} aria-hidden="true" />
          <input
            type="search"
            placeholder="Filter operations"
            aria-label="Filter operations"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        </label>
        <span className="hint">
          {value.size} of {ops.length} selected
        </span>
        <button
          type="button"
          className="link"
          onClick={() =>
            set(
              ops.filter((o) => !o.write).map((o) => o.id),
              true,
            )
          }
        >
          All read
        </button>
        <button
          type="button"
          className="link"
          onClick={() => onChange(new Set())}
        >
          Clear
        </button>
      </div>
      {areas.map(([area, list]) => {
        const shown = list.filter(match)
        if (shown.length === 0) return null
        const on = list.filter((o) => value.has(o.id)).length
        return (
          <fieldset key={area} className="picker-area">
            <legend>
              {area}{' '}
              <span className="hint">
                {on}/{list.length}
              </span>
            </legend>
            <div className="picker-area-tools">
              <button
                type="button"
                className="link"
                onClick={() =>
                  set(
                    list.filter((o) => !o.write).map((o) => o.id),
                    true,
                  )
                }
              >
                Read
              </button>
              <button
                type="button"
                className="link"
                onClick={() =>
                  set(
                    list.map((o) => o.id),
                    true,
                  )
                }
              >
                All
              </button>
              <button
                type="button"
                className="link"
                onClick={() =>
                  set(
                    list.map((o) => o.id),
                    false,
                  )
                }
              >
                None
              </button>
            </div>
            {shown.map((o) => (
              <label key={o.id} className="picker-op">
                <input
                  type="checkbox"
                  checked={value.has(o.id)}
                  onChange={(e) => set([o.id], e.target.checked)}
                />
                <Method m={o.method} />
                <span className="picker-op-text">
                  <span>{o.summary}</span>
                  <span className="hint mono">
                    {o.id} · {o.path}
                  </span>
                </span>
              </label>
            ))}
          </fieldset>
        )
      })}
    </div>
  )
}

function KeyForm({
  ops,
  editing,
  onDone,
  onCancel,
}: {
  ops: APIOperation[]
  editing: APIKey | null
  onDone: (created?: { key: APIKey; token: string }) => void
  onCancel: () => void
}) {
  const [name, setName] = useState(editing?.name ?? '')
  const [perms, setPerms] = useState(new Set(editing?.permissions ?? []))
  const [expires, setExpires] = useState(
    editing?.expires_at?.slice(0, 10) ?? '',
  )
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    setFields({})
    const input: APIKeyInput = {
      name,
      permissions: [...perms],
      expires_at: expires || null,
    }
    try {
      if (editing) {
        await api.updateAPIKey(editing.id, input)
        onDone()
      } else {
        onDone(await api.createAPIKey(input))
      }
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h1>{editing ? `Edit “${editing.name}”` : 'New API key'}</h1>
      <div className="actions">
        <label className="grow">
          Name
          <input
            required
            placeholder="e.g. Deploy script, Uptime monitor"
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
          {fields.name && <span className="field-error">{fields.name}</span>}
        </label>
        <label>
          Expires (optional)
          <input
            type="date"
            value={expires}
            onChange={(e) => setExpires(e.target.value)}
          />
          {fields.expires_at && (
            <span className="field-error">{fields.expires_at}</span>
          )}
        </label>
      </div>
      <div>
        <h2>What this key may do</h2>
        <p className="hint">
          Give it only what the program needs. Changes to hosts, folders, access
          and DNS are staged; the program also needs{' '}
          <span className="mono">config.apply</span> to send them to Caddy.
        </p>
      </div>
      <PermissionPicker ops={ops} value={perms} onChange={setPerms} />
      {fields.permissions && (
        <p className="field-error">{fields.permissions}</p>
      )}
      {error && <p className="error">{error}</p>}
      <div className="actions">
        <button disabled={busy}>
          {editing ? 'Save changes' : 'Create key'}
        </button>
        <button type="button" className="secondary" onClick={onCancel}>
          Cancel
        </button>
      </div>
    </form>
  )
}

function NewToken({
  created,
  ops,
  onClose,
}: {
  created: { key: APIKey; token: string }
  ops: APIOperation[]
  onClose: () => void
}) {
  // An example the key is actually allowed to run: its first plain GET.
  const tryOp = ops.find(
    (o) =>
      o.method === 'GET' &&
      !o.path.includes('{') &&
      created.key.permissions.includes(o.id),
  )
  const example = `curl -H "Authorization: Bearer ${created.token}" ${location.origin}${tryOp ? tryOp.path : '/api/…'}`
  return (
    <section className="card token-card" role="status">
      <h1>
        <KeyRound size={20} aria-hidden="true" /> “{created.key.name}” is ready
      </h1>
      <p className="notice">
        Copy the key now. Switchyard keeps only a fingerprint of it, so it can’t
        be shown again. If it’s lost, revoke it and make a new one.
      </p>
      <div className="token-row">
        <code className="token">{created.token}</code>
        <CopyButton text={created.token} label="Copy key" />
      </div>
      <p className="hint">Try it:</p>
      <div className="token-row">
        <code className="token">{example}</code>
        <CopyButton text={example} />
      </div>
      <div className="actions">
        <button onClick={onClose}>Done</button>
        <a href="#/api-docs">API reference</a>
      </div>
    </section>
  )
}

export function ApiKeysPage() {
  const [keys, setKeys] = useState<APIKey[] | null>(null)
  const [ops, setOps] = useState<APIOperation[]>([])
  const [mode, setMode] = useState<'list' | 'new' | APIKey>('list')
  const [created, setCreated] = useState<{ key: APIKey; token: string } | null>(
    null,
  )
  const [open, setOpen] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  function load() {
    api
      .apiKeys()
      .then(setKeys)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(() => {
    load()
    api
      .keyOperations()
      .then(setOps)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  async function revoke(k: APIKey) {
    if (
      !confirm(
        `Revoke “${k.name}”? Programs using it stop working at once. This can’t be undone.`,
      )
    )
      return
    try {
      await api.revokeAPIKey(k.id)
      load()
    } catch (err) {
      setError(message(err))
    }
  }

  const opName = useMemo(() => new Map(ops.map((o) => [o.id, o])), [ops])

  return (
    <div className="page">
      <PageHeader
        title="API keys"
        subtitle="Let other programs manage Switchyard, each with only the operations you choose."
        actions={
          <>
            <a className="button secondary" href="#/api-docs">
              API reference
            </a>
            {mode === 'list' && (
              <button onClick={() => (setCreated(null), setMode('new'))}>
                <Plus size={18} aria-hidden="true" /> New key
              </button>
            )}
          </>
        }
      />
      {error && <p className="error">{error}</p>}
      {created && (
        <NewToken
          created={created}
          ops={ops}
          onClose={() => setCreated(null)}
        />
      )}
      {mode !== 'list' ? (
        <KeyForm
          ops={ops}
          editing={mode === 'new' ? null : mode}
          onCancel={() => setMode('list')}
          onDone={(c) => {
            setMode('list')
            if (c) setCreated(c)
            load()
          }}
        />
      ) : (
        <section className="card">
          {!keys ? (
            <p className="hint">Loading…</p>
          ) : keys.length === 0 ? (
            <div className="empty">
              <p>No API keys yet.</p>
              <p className="hint">
                Make one for each program, such as a deploy script or a
                monitoring tool, so you can see what each does and revoke it on
                its own.
              </p>
            </div>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Key</th>
                    <th>Permissions</th>
                    <th>Last used</th>
                    <th>Expires</th>
                    <th>Status</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {keys.map((k) => {
                    const st = keyState(k)
                    const live = st.label === 'Active'
                    return (
                      <tr key={k.id} className={live ? '' : 'disabled'}>
                        <td>
                          <strong>{k.name}</strong>
                          <div className="hint">
                            by {k.created_by},{' '}
                            {new Date(k.created_at).toLocaleDateString()}
                          </div>
                        </td>
                        <td className="mono nowrap">{k.prefix}…</td>
                        <td>
                          <button
                            className="link"
                            onClick={() => setOpen(open === k.id ? null : k.id)}
                          >
                            {k.permissions.length} operation
                            {k.permissions.length === 1 ? '' : 's'}
                          </button>
                          {open === k.id && (
                            <ul className="perm-list">
                              {k.permissions.map((p) => (
                                <li key={p}>
                                  {opName.get(p) && (
                                    <Method m={opName.get(p)!.method} />
                                  )}{' '}
                                  <span className="mono">{p}</span>
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                        <td>
                          {when(k.last_used_at)}
                          {k.last_used_ip && (
                            <div className="hint">from {k.last_used_ip}</div>
                          )}
                        </td>
                        <td className="nowrap">
                          {k.expires_at
                            ? new Date(k.expires_at).toLocaleDateString()
                            : 'Never'}
                        </td>
                        <td>
                          <span className={`badge ${st.cls}`}>{st.label}</span>
                        </td>
                        <td>
                          {live && (
                            <div className="row-actions">
                              <button
                                className="link"
                                onClick={() => (setCreated(null), setMode(k))}
                              >
                                Edit
                              </button>
                              <button
                                className="link danger"
                                onClick={() => void revoke(k)}
                              >
                                Revoke
                              </button>
                            </div>
                          )}
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}
    </div>
  )
}

/** The API reference, built from the OpenAPI document the server publishes. */
export function ApiDocsPage() {
  const [doc, setDoc] = useState<OpenAPIDoc | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [q, setQ] = useState('')
  useEffect(() => {
    api
      .openapi()
      .then(setDoc)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  const groups = useMemo(() => {
    const m = new Map<
      string,
      {
        method: string
        path: string
        op: OpenAPIDoc['paths'][string][string]
      }[]
    >()
    for (const [path, item] of Object.entries(doc?.paths ?? {}))
      for (const [method, op] of Object.entries(item)) {
        const area = op.tags[0]
        m.set(area, [
          ...(m.get(area) ?? []),
          { method: method.toUpperCase(), path, op },
        ])
      }
    // In the app's own order (the document's tags), not by path.
    const order = (doc?.tags ?? []).map((t) => t.name)
    return [...m.entries()].sort(
      ([a], [b]) =>
        (order.indexOf(a) + 1 || order.length + 1) -
        (order.indexOf(b) + 1 || order.length + 1),
    )
  }, [doc])
  const term = q.trim().toLowerCase()
  const base = location.origin

  return (
    <div className="page">
      <PageHeader
        title="API reference"
        subtitle="Every endpoint, with the permission an API key needs for it."
        actions={
          <a
            className="button secondary"
            href="/api/openapi.json"
            target="_blank"
            rel="noreferrer"
          >
            OpenAPI (JSON)
          </a>
        }
      />
      {error && <p className="error">{error}</p>}
      <section className="card">
        <h2>Getting started</h2>
        <ol className="steps">
          <li>
            An admin makes a key on <a href="#/api-keys">API keys</a> and picks
            what it may do.
          </li>
          <li>
            Send it with every request: <code>Authorization: Bearer sy_…</code>{' '}
            (or <code>X-API-Key: sy_…</code>).
          </li>
          <li>
            Bodies and answers are JSON. Errors look like{' '}
            <code>{'{"error": "missing_permission", "message": "…"}'}</code>.
          </li>
          <li>
            Changes to hosts, folders, access and DNS are staged. Call{' '}
            <code>POST /api/config/apply</code> (
            <span className="mono">config.apply</span>) to send them to Caddy.
          </li>
        </ol>
        <div className="token-row">
          <code className="token">
            {`curl -X POST ${base}/api/hosts -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \\
  -d '{"type":"proxy","enabled":true,"domains":["app.example.com"],"tls_mode":"auto","upstreams":[{"scheme":"http","host":"10.0.0.5","port":8080}]}'
curl -X POST ${base}/api/config/apply -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" -d '{"note":"from my script"}'`}
          </code>
        </div>
        <p className="hint">
          The OpenAPI document can generate clients and import into Postman or
          Insomnia.
        </p>
      </section>
      <label className="picker-search wide">
        <Search size={16} aria-hidden="true" />
        <input
          type="search"
          placeholder="Filter endpoints"
          aria-label="Filter endpoints"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </label>
      {groups.map(([area, list]) => {
        const shown = list.filter(
          (e) =>
            !term ||
            [e.path, e.op.operationId, e.op.summary, area].some((x) =>
              x.toLowerCase().includes(term),
            ),
        )
        if (shown.length === 0) return null
        return (
          <section key={area} className="card">
            <h2>{area}</h2>
            <div className="table-wrap">
              <table className="api-table">
                <thead>
                  <tr>
                    <th>Endpoint</th>
                    <th>What it does</th>
                    <th>API key permission</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map((e) => (
                    <tr key={e.method + e.path}>
                      <td className="nowrap">
                        <Method m={e.method} />{' '}
                        <span className="mono">{e.path}</span>
                        {e.op.parameters.some((p) => p.in === 'query') && (
                          <div className="hint mono">
                            ?
                            {e.op.parameters
                              .filter((p) => p.in === 'query')
                              .map((p) => p.name)
                              .join('&')}
                          </div>
                        )}
                      </td>
                      <td>
                        {e.op.summary}
                        <div className="hint">
                          {e.op.description.split('.')[0]}.
                        </div>
                      </td>
                      <td>
                        {e.op['x-keyable'] ? (
                          <span className="mono">{e.op.operationId}</span>
                        ) : (
                          <span className="hint">Not for keys</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        )
      })}
    </div>
  )
}
