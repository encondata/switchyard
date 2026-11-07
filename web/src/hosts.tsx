import { useEffect, useState, type DragEvent, type FormEvent } from 'react'
import {
  api,
  ApiError,
  effectivePolicies,
  folderAndBelow,
  folderDNSProvider,
  folderTree,
  message,
  newHost,
  type AccessPolicy,
  type CertStatus,
  type DNSProvider,
  type HeaderRule,
  type Folder,
  type Host,
  type HostView,
  type Upstream,
} from './api'
import { HeaderEditor } from './headers'

const typeLabel = { proxy: 'Proxy', redirect: 'Redirect', '404': '404' }
const tlsLabel = {
  auto: 'Automatic',
  dns: 'DNS challenge',
  internal: 'Internal CA',
  off: 'Off',
}

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

export function PolicyBadge({
  p,
  from,
}: {
  p: AccessPolicy
  from?: Folder | null
}) {
  const kind = p.mode === 'allow_only' ? 'Allow only' : 'Deny'
  const title = `${kind}: ${p.rules.join(', ')}${from ? ` — inherited from “${from.name}”` : ''}`
  return (
    <span className={`badge policy-${p.mode}`} title={title}>
      {p.name}
      {from && ' ↑'}
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

// Folder filter: everything, hosts without a folder, or a folder (and below).
type Filter = 'all' | 'unfiled' | number

function FolderForm({
  folder,
  parentId,
  folders,
  policies,
  onDone,
}: {
  folder: Folder | null
  parentId: number | null
  folders: Folder[]
  policies: AccessPolicy[]
  onDone: (changed: boolean) => void
}) {
  const [name, setName] = useState(folder?.name ?? '')
  const [parent, setParent] = useState<number | null>(
    folder ? folder.parent_id : parentId,
  )
  const [policyIds, setPolicyIds] = useState<number[]>(folder?.policy_ids ?? [])
  const [dnsProvider, setDnsProvider] = useState<number | null>(
    folder?.dns_provider_id ?? null,
  )
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [reqHeaders, setReqHeaders] = useState<HeaderRule[]>(
    folder?.request_headers ?? [],
  )
  const [respHeaders, setRespHeaders] = useState<HeaderRule[]>(
    folder?.response_headers ?? [],
  )
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})

  useEffect(() => {
    api
      .dnsProviders()
      .then((r) => setProviders(r.providers))
      .catch(() => setProviders([]))
  }, [])

  // A folder can't move inside itself or its own subfolders.
  const blocked = folder
    ? folderAndBelow(folder.id, folders)
    : new Set<number>()

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setFields({})
    try {
      await api.saveFolder({
        id: folder?.id ?? 0,
        name,
        parent_id: parent,
        policy_ids: policyIds,
        dns_provider_id: dnsProvider,
        request_headers: reqHeaders,
        response_headers: respHeaders,
      })
      onDone(true)
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  return (
    <form className="folder-form" onSubmit={submit}>
      <h2>{folder ? `Edit “${folder.name}”` : 'New folder'}</h2>
      <label>
        Name
        <input
          autoFocus
          required
          value={name}
          onChange={(e) => setName(e.target.value)}
        />
        {fields.name && <span className="field-error">{fields.name}</span>}
      </label>
      <label>
        Inside
        <select
          value={parent ?? ''}
          onChange={(e) =>
            setParent(e.target.value ? Number(e.target.value) : null)
          }
        >
          <option value="">(top level)</option>
          {folderTree(folders).map(({ folder: f, depth }) => (
            <option key={f.id} value={f.id} disabled={blocked.has(f.id)}>
              {'  '.repeat(depth)}
              {f.name}
            </option>
          ))}
        </select>
        {fields.parent_id && (
          <span className="field-error">{fields.parent_id}</span>
        )}
      </label>
      <fieldset>
        <legend>Access policies</legend>
        {policies.length === 0 && (
          <p className="hint">
            No policies yet. Create them on the <a href="#/access">Access</a>{' '}
            page.
          </p>
        )}
        {policies.map((p) => (
          <label className="inline" key={p.id}>
            <input
              type="checkbox"
              checked={policyIds.includes(p.id)}
              onChange={(e) =>
                setPolicyIds(
                  e.target.checked
                    ? [...policyIds, p.id]
                    : policyIds.filter((id) => id !== p.id),
                )
              }
            />
            <PolicyBadge p={p} />
            <span className="hint">{p.rules.slice(0, 3).join(', ')}</span>
          </label>
        ))}
        <p className="hint">
          Every host in this folder and its subfolders gets these policies.
        </p>
      </fieldset>
      <fieldset>
        <legend>Default headers</legend>
        <HeaderEditor
          label="Response headers"
          hint="Sent to visitors of every host inside. A host’s own rule for the same header wins."
          rules={respHeaders}
          onChange={setRespHeaders}
          error={fields.response_headers}
        />
        <HeaderEditor
          label="Request headers (proxy hosts)"
          hint="Sent to the backends of proxy hosts inside."
          rules={reqHeaders}
          onChange={setReqHeaders}
          error={fields.request_headers}
        />
      </fieldset>
      <label>
        Default DNS provider
        <select
          value={dnsProvider ?? ''}
          onChange={(e) =>
            setDnsProvider(e.target.value ? Number(e.target.value) : null)
          }
        >
          <option value="">(none — inherit from the folder above)</option>
          {providers.map((p) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
        <span className="hint">
          Hosts inside that use the DNS challenge without choosing a provider
          use this one.
        </span>
        {fields.dns_provider_id && (
          <span className="field-error">{fields.dns_provider_id}</span>
        )}
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        <button>Save folder</button>
        <button
          type="button"
          className="secondary"
          onClick={() => onDone(false)}
        >
          Cancel
        </button>
      </div>
    </form>
  )
}

export function HostList({
  canEdit,
  isAdmin = false,
  onChanged,
}: {
  canEdit: boolean
  isAdmin?: boolean
  onChanged: () => void
}) {
  const [hosts, setHosts] = useState<HostView[] | null>(null)
  const [folders, setFolders] = useState<Folder[]>([])
  const [policies, setPolicies] = useState<AccessPolicy[]>([])
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  const [editing, setEditing] = useState<{
    folder: Folder | null
    parentId: number | null
  } | null>(null)
  const [dropTarget, setDropTarget] = useState<Filter | null>(null)

  function load() {
    Promise.all([api.hosts(), api.folders(), api.policies()])
      .then(([h, f, p]) => {
        setHosts(h)
        setFolders(f)
        setPolicies(p)
      })
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function run(action: () => Promise<unknown>, done?: string) {
    setError(null)
    setInfo(null)
    try {
      await action()
      if (done) setInfo(done)
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  const selected =
    typeof filter === 'number' ? folders.find((f) => f.id === filter) : null
  const inFilter = (h: HostView) => {
    if (filter === 'all') return true
    if (filter === 'unfiled') return h.folder_id == null
    return (
      h.folder_id != null && folderAndBelow(filter, folders).has(h.folder_id)
    )
  }
  const q = search.trim().toLowerCase()
  const shown = (hosts ?? []).filter(
    (h) => inFilter(h) && (!q || h.domains.some((d) => d.includes(q))),
  )

  // Drag a host row onto a folder (or "Unfiled") to move it.
  function onDrop(e: DragEvent, to: Filter) {
    e.preventDefault()
    setDropTarget(null)
    const id = Number(e.dataTransfer.getData('text/x-cpm-host'))
    const h = hosts?.find((x) => x.id === id)
    if (!h || to === 'all') return
    const folderId = to === 'unfiled' ? null : to
    if (h.folder_id === folderId) return
    const name =
      folderId == null
        ? 'Unfiled'
        : folders.find((f) => f.id === folderId)?.name
    void run(
      () => api.moveHost(id, folderId),
      `Moved ${h.domains[0]} to ${name}.`,
    )
  }
  const dropProps = (to: Filter) =>
    canEdit && to !== 'all'
      ? {
          onDragOver: (e: DragEvent) => {
            e.preventDefault()
            setDropTarget(to)
          },
          onDragLeave: () => setDropTarget(null),
          onDrop: (e: DragEvent) => onDrop(e, to),
        }
      : {}

  const countIn = (id: number) => {
    const ids = folderAndBelow(id, folders)
    return (hosts ?? []).filter(
      (h) => h.folder_id != null && ids.has(h.folder_id),
    ).length
  }
  const navItem = (key: Filter, label: string, count: number, depth = 0) => (
    <li key={String(key)}>
      <button
        className={`folder-item${filter === key ? ' active' : ''}${dropTarget === key ? ' drop' : ''}`}
        style={{ paddingLeft: `${0.6 + depth * 0.9}rem` }}
        onClick={() => setFilter(key)}
        {...dropProps(key)}
      >
        <span className="folder-name">{label}</span>
        <span className="count">{count}</span>
      </button>
    </li>
  )

  return (
    <div className="hosts-layout">
      <aside className="card folders">
        <div className="toolbar">
          <h2>Folders</h2>
          {canEdit && (
            <button
              className="link"
              onClick={() =>
                setEditing({
                  folder: null,
                  parentId: typeof filter === 'number' ? filter : null,
                })
              }
            >
              + New
            </button>
          )}
        </div>
        <ul className="folder-list">
          {navItem('all', 'All hosts', hosts?.length ?? 0)}
          {navItem(
            'unfiled',
            'Unfiled',
            (hosts ?? []).filter((h) => h.folder_id == null).length,
          )}
          {folderTree(folders).map(({ folder: f, depth }) =>
            navItem(f.id, f.name, countIn(f.id), depth),
          )}
        </ul>
        {canEdit && folders.length > 0 && (
          <p className="hint">Drag hosts onto a folder to move them.</p>
        )}
      </aside>

      <section className="card">
        {editing ? (
          <FolderForm
            folder={editing.folder}
            parentId={editing.parentId}
            folders={folders}
            policies={policies}
            onDone={(changed) => {
              setEditing(null)
              if (changed) {
                load()
                onChanged()
              }
            }}
          />
        ) : (
          <>
            <div className="toolbar">
              <h1>
                {selected
                  ? selected.name
                  : filter === 'unfiled'
                    ? 'Unfiled'
                    : 'Hosts'}
              </h1>
              <input
                className="search"
                placeholder="Filter by domain"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
              {isAdmin && (
                <a className="button secondary" href="#/import">
                  Import from NPM
                </a>
              )}
              {canEdit && (
                <a
                  className="button"
                  href={`#/hosts/new${selected ? `?folder=${selected.id}` : ''}`}
                >
                  Add host
                </a>
              )}
            </div>
            {selected && (
              <div className="folder-bar">
                <span className="hint">Policies:</span>
                {selected.policy_ids.length === 0 && (
                  <span className="hint">none</span>
                )}
                {effectivePolicies(
                  { folder_id: selected.id, policy_ids: [] },
                  folders,
                  policies,
                ).map(({ policy, from }) => (
                  <PolicyBadge
                    key={policy.id}
                    p={policy}
                    from={from?.id === selected.id ? null : from}
                  />
                ))}
                {canEdit && (
                  <span className="folder-actions">
                    <button
                      className="link"
                      onClick={() =>
                        setEditing({ folder: selected, parentId: null })
                      }
                    >
                      Edit folder
                    </button>
                    <button
                      className="link"
                      onClick={() =>
                        run(
                          () => api.setFolderEnabled(selected.id, true),
                          `Enabled every host in “${selected.name}”.`,
                        )
                      }
                    >
                      Enable all
                    </button>
                    <button
                      className="link"
                      onClick={() =>
                        run(
                          () => api.setFolderEnabled(selected.id, false),
                          `Disabled every host in “${selected.name}”.`,
                        )
                      }
                    >
                      Disable all
                    </button>
                    <button
                      className="link danger"
                      onClick={() => {
                        if (confirm(`Delete the folder “${selected.name}”?`))
                          void run(() => api.deleteFolder(selected.id)).then(
                            () => setFilter('all'),
                          )
                      }}
                    >
                      Delete
                    </button>
                  </span>
                )}
              </div>
            )}
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            {info && (
              <p className="success" role="status">
                {info} Review and apply to send it to Caddy.
              </p>
            )}
            {!hosts && !error && <p>Loading…</p>}
            {hosts && shown.length === 0 && (
              <div className="empty">
                <p>{hosts.length === 0 ? 'No hosts yet.' : 'No hosts here.'}</p>
                {canEdit && hosts.length === 0 && (
                  <p className="hint">
                    Add a proxy host, then review and apply the change to send
                    it to Caddy.
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
                      <th>Access</th>
                      <th>Status</th>
                      {canEdit && <th aria-label="Actions" />}
                    </tr>
                  </thead>
                  <tbody>
                    {shown.map((h) => {
                      const eff = effectivePolicies(h, folders, policies)
                      const folder = folders.find((f) => f.id === h.folder_id)
                      return (
                        <tr
                          key={h.id}
                          className={h.enabled ? '' : 'disabled'}
                          draggable={canEdit}
                          onDragStart={(e) =>
                            e.dataTransfer.setData(
                              'text/x-cpm-host',
                              String(h.id),
                            )
                          }
                        >
                          <td>
                            {h.domains.map((d, i) => (
                              <div key={d}>
                                {canEdit ? (
                                  <a href={`#/hosts/${h.id}`}>{d}</a>
                                ) : (
                                  d
                                )}{' '}
                                {h.enabled && h.certs[i] && (
                                  <CertBadge c={h.certs[i]} />
                                )}
                              </div>
                            ))}
                            {filter === 'all' && folder && (
                              <div className="hint">in {folder.name}</div>
                            )}
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
                            {eff.length === 0 && (
                              <span className="hint">Open</span>
                            )}
                            {eff.map(({ policy, from }) => (
                              <PolicyBadge
                                key={policy.id}
                                p={policy}
                                from={from}
                              />
                            ))}
                          </td>
                          <td>
                            {canEdit ? (
                              <label className="switch">
                                <input
                                  type="checkbox"
                                  checked={h.enabled}
                                  onChange={() =>
                                    run(() =>
                                      api.saveHost({
                                        ...h,
                                        enabled: !h.enabled,
                                      }),
                                    )
                                  }
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
                                <a href={`#/hosts/new?clone=${h.id}`}>Clone</a>
                                <button
                                  className="link danger"
                                  onClick={() => {
                                    if (
                                      confirm(
                                        `Delete the host for ${h.domains.join(', ')}?`,
                                      )
                                    )
                                      void run(() => api.deleteHost(h.id))
                                  }}
                                >
                                  Delete
                                </button>
                              </div>
                            </td>
                          )}
                        </tr>
                      )
                    })}
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

function FieldError({ msg }: { msg?: string }) {
  return msg ? <span className="field-error">{msg}</span> : null
}

export function HostEditor({
  id,
  folderId,
  cloneId,
  isAdmin,
  onSaved,
}: {
  id: number | null
  folderId?: number | null
  /** Start a new host as a copy of this one (without its domains). */
  cloneId?: number | null
  isAdmin: boolean
  onSaved: () => void
}) {
  const [host, setHost] = useState<Host | null>(
    id ? null : { ...newHost(), folder_id: folderId ?? null },
  )
  const [domains, setDomains] = useState('')
  const [folders, setFolders] = useState<Folder[]>([])
  const [policies, setPolicies] = useState<AccessPolicy[]>([])
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    Promise.all([api.folders(), api.policies(), api.dnsProviders()])
      .then(([f, p, d]) => {
        setFolders(f)
        setPolicies(p)
        setProviders(d.providers)
      })
      .catch((err: unknown) => setError(message(err)))
    const source = id ?? cloneId
    if (!source) return
    api
      .host(source)
      .then((h) => {
        if (id) {
          setHost(h)
          setDomains(h.domains.join('\n'))
        } else {
          // A clone: same settings, new domains (domains must be unique).
          setHost({ ...h, id: 0, domains: [], enabled: true })
          setDomains('')
        }
      })
      .catch((err: unknown) => setError(message(err)))
  }, [id, cloneId])

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
  const inherited = effectivePolicies(
    { folder_id: host.folder_id, policy_ids: [] },
    folders,
    policies,
  )

  return (
    <form className="card" onSubmit={submit}>
      <h1>{id ? 'Edit host' : cloneId ? 'Clone host' : 'Add host'}</h1>
      {!isAdmin && !!host.advanced_json && (
        <p className="notice">
          This host has advanced JSON, so only an admin can change it.
        </p>
      )}
      {cloneId && !id && (
        <p className="notice">
          A copy of host #{cloneId}. Enter the new host’s domains.
        </p>
      )}

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
                    { ...host.upstreams[0], host: '' },
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
          {host.upstreams.length > 1 && (
            <p className="hint">
              All upstreams of a host use the same scheme and TLS settings.
            </p>
          )}
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
            <option value="dns">
              DNS challenge (Cloudflare) — for wildcards and internal names
            </option>
            <option value="internal">
              Internal CA — for LAN-only names; browsers will warn
            </option>
            <option value="off">Off — plain HTTP on port 80 only</option>
          </select>
        </label>
        {host.tls_mode === 'dns' && (
          <label>
            DNS provider
            <select
              value={host.dns_provider_id ?? ''}
              onChange={(e) =>
                set({
                  dns_provider_id: e.target.value
                    ? Number(e.target.value)
                    : null,
                })
              }
            >
              <option value="">
                {(() => {
                  const id = folderDNSProvider(host.folder_id, folders)
                  const p = providers.find((x) => x.id === id)
                  return p
                    ? `Folder default (${p.name})`
                    : 'Folder default (none set — choose one)'
                })()}
              </option>
              {providers.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name}
                </option>
              ))}
            </select>
            <FieldError msg={fields.dns_provider_id} />
            {providers.length === 0 && (
              <span className="hint">
                No DNS providers yet. Add your Cloudflare token on the{' '}
                <a href="#/dns">DNS</a> page.
              </span>
            )}
          </label>
        )}
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

      <fieldset>
        <legend>Folder and access</legend>
        <label>
          Folder
          <select
            value={host.folder_id ?? ''}
            onChange={(e) =>
              set({ folder_id: e.target.value ? Number(e.target.value) : null })
            }
          >
            <option value="">Unfiled</option>
            {folderTree(folders).map(({ folder: f, depth }) => (
              <option key={f.id} value={f.id}>
                {'  '.repeat(depth)}
                {f.name}
              </option>
            ))}
          </select>
          <FieldError msg={fields.folder_id} />
        </label>
        {inherited.length > 0 && (
          <div>
            <span className="hint">From the folder: </span>
            {inherited.map(({ policy, from }) => (
              <PolicyBadge key={policy.id} p={policy} from={from} />
            ))}
          </div>
        )}
        <div>
          <span className="hint">Also apply to this host:</span>
          {policies.length === 0 && (
            <p className="hint">
              No policies yet. Create them on the <a href="#/access">Access</a>{' '}
              page.
            </p>
          )}
          {policies.map((p) => (
            <label className="inline" key={p.id}>
              <input
                type="checkbox"
                checked={host.policy_ids.includes(p.id)}
                onChange={(e) =>
                  set({
                    policy_ids: e.target.checked
                      ? [...host.policy_ids, p.id]
                      : host.policy_ids.filter((x) => x !== p.id),
                  })
                }
              />
              <PolicyBadge p={p} />
              <span className="hint">{p.rules.slice(0, 3).join(', ')}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <fieldset>
        <legend>Headers</legend>
        <HeaderEditor
          label="Response headers"
          hint="Sent to visitors. Values can use Caddy placeholders. Folder defaults apply first."
          rules={host.response_headers}
          onChange={(r) => set({ response_headers: r })}
          error={fields.response_headers}
        />
        {host.type === 'proxy' && (
          <HeaderEditor
            label="Request headers"
            hint="Sent to the backend, e.g. X-Real-IP = {http.request.remote.host}."
            rules={host.request_headers}
            onChange={(r) => set({ request_headers: r })}
            error={fields.request_headers}
          />
        )}
      </fieldset>

      {host.type === 'proxy' && (
        <fieldset>
          <legend>Health checks</legend>
          <div className="actions">
            <label>
              Check path <span className="hint">(empty = off)</span>
              <input
                className="mono"
                placeholder="/health"
                value={host.health_check_path}
                onChange={(e) => set({ health_check_path: e.target.value })}
              />
            </label>
            <label>
              Every (seconds)
              <input
                type="number"
                min={5}
                max={3600}
                value={host.health_check_interval}
                onChange={(e) =>
                  set({ health_check_interval: Number(e.target.value) })
                }
              />
            </label>
          </div>
          <FieldError
            msg={fields.health_check_path ?? fields.health_check_interval}
          />
          <span className="hint">
            Caddy requests this path on each upstream and stops sending traffic
            to ones that don’t answer with a 2xx status.
          </span>
        </fieldset>
      )}

      <details open={!!host.advanced_json}>
        <summary>Advanced: raw Caddy routes</summary>
        <label>
          JSON array of Caddy routes, run after the access rules and before this
          host’s handler.{' '}
          {!isAdmin && <span className="hint">(admins only)</span>}
          <textarea
            rows={6}
            className="mono"
            readOnly={!isAdmin}
            placeholder={
              '[{"match":[{"path":["/old/*"]}],"handle":[{"handler":"static_response","status_code":"410"}],"terminal":true}]'
            }
            value={host.advanced_json}
            onChange={(e) => set({ advanced_json: e.target.value })}
          />
          <FieldError msg={fields.advanced_json} />
          <span className="hint">
            CPM checks the shape when you save; Caddy checks the rest when you
            apply. If Caddy rejects it, every host keeps running the previous
            config.
          </span>
        </label>
      </details>

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
