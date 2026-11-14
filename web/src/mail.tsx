import { useEffect, useState, type FormEvent } from 'react'
import { Mail, RefreshCw } from 'lucide-react'
import {
  api,
  ApiError,
  message,
  type CFRecord,
  type DNSProvider,
  type MailCheck,
  type MailDomain,
  type MailRecord,
} from './api'

const domainStatus: Record<MailDomain['status'], [string, string]> = {
  '': ['Not checked', 'cert-not_needed'],
  ok: ['All set', 'cert-valid'],
  incomplete: ['Records missing', 'cert-pending'],
  conflict: ['Needs a decision', 'cert-expired'],
  error: ['Check failed', 'cert-expired'],
}

const recordState: Record<MailRecord['state'], [string, string]> = {
  ok: ['OK', 'cert-valid'],
  missing: ['Will add', 'cert-pending'],
  conflict: ['In the way', 'cert-expired'],
  needs_value: ['Needs ownership proof', 'cert-pending'],
}

/** A record name relative to the domain: @ for the domain itself. */
function short(name: string, domain: string): string {
  const n = name.toLowerCase().replace(/\.$/, '')
  if (n === domain) return '@'
  return n.endsWith('.' + domain) ? n.slice(0, -domain.length - 1) : n
}

function unquote(s: string): string {
  return s.length >= 2 && s.startsWith('"') && s.endsWith('"')
    ? s.slice(1, -1)
    : s
}

function applyLabel(add: number, del: number): string {
  const n = (k: number) => `${k} record${k === 1 ? '' : 's'}`
  if (add && del) return `Add ${add} and delete ${n(del)}`
  if (del) return `Delete ${n(del)}`
  if (add) return `Add ${n(add)}`
  return 'Nothing to change'
}

function describe(r: CFRecord, domain: string): string {
  const prio = r.priority != null ? `${r.priority} ` : ''
  const proxied = r.proxied ? ' (proxied)' : ''
  return `${r.type} ${short(r.name, domain)} → ${prio}${unquote(r.content)}${proxied}`
}

/**
 * Mail domains: domains moving to Purelymail, with their DNS at Cloudflare.
 * Switchyard checks a zone against Purelymail's records and adds what's
 * missing; records in the way are only deleted when you tick them.
 */
export function MailPage({
  canEdit,
  isAdmin,
}: {
  canEdit: boolean
  isAdmin: boolean
}) {
  const [domains, setDomains] = useState<MailDomain[] | null>(null)
  const [providers, setProviders] = useState<DNSProvider[]>([])
  const [ownership, setOwnership] = useState<string | null>(null)
  const [check, setCheck] = useState<MailCheck | null>(null)
  const [checking, setChecking] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  function load() {
    api
      .mailDomains()
      .then(setDomains)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(() => {
    load()
    api
      .dnsProviders()
      .then((r) => setProviders(r.providers))
      .catch(() => undefined)
    api
      .mailSettings()
      .then((s) => setOwnership(s.ownership))
      .catch(() => setOwnership(''))
  }, [])

  async function open(d: MailDomain) {
    setError(null)
    setChecking(d.id)
    try {
      setCheck(await api.checkMailDomain(d.id))
    } catch (err) {
      setError(`${d.domain}: ${message(err)}`)
      setCheck(null)
    } finally {
      setChecking(null)
      load()
    }
  }

  async function remove(d: MailDomain) {
    if (
      !confirm(
        `Take ${d.domain} off the list? Its DNS records stay as they are in Cloudflare.`,
      )
    )
      return
    try {
      await api.deleteMailDomain(d.id)
      if (check?.domain.id === d.id) setCheck(null)
      load()
    } catch (err) {
      setError(message(err))
    }
  }

  const providerName = (id: number) =>
    providers.find((p) => p.id === id)?.name ?? `#${id}`

  return (
    <div className="stack">
      <OwnershipCard
        value={ownership}
        isAdmin={isAdmin}
        onSaved={(v) => {
          setOwnership(v)
          if (check) void open(check.domain)
        }}
      />
      <section className="card">
        <h1>Mail domains</h1>
        <p className="hint">
          Domains whose mail is at Purelymail, with their DNS at Cloudflare.
          Switchyard checks each domain’s DNS against the records Purelymail
          needs (mail server, SPF, ownership proof, three DKIM keys and DMARC)
          and adds the missing ones. Nothing is deleted unless you choose to
          replace it.
        </p>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        {domains && domains.length > 0 && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Domain</th>
                  <th>DNS provider</th>
                  <th>Records</th>
                  <th>Checked</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {domains.map((d) => {
                  const [text, cls] = domainStatus[d.status] ?? [d.status, '']
                  return (
                    <tr
                      key={d.id}
                      className={
                        check?.domain.id === d.id ? 'selected-row' : undefined
                      }
                    >
                      <td>
                        <span className="mono">{d.domain}</span>
                        {d.zone_name !== d.domain && (
                          <div className="hint">
                            in zone <span className="mono">{d.zone_name}</span>
                          </div>
                        )}
                      </td>
                      <td>{providerName(d.dns_provider_id)}</td>
                      <td>
                        <span className={`badge ${cls}`}>{text}</span>
                        {d.status === 'error' && d.status_detail && (
                          <div className="hint">{d.status_detail}</div>
                        )}
                      </td>
                      <td className="hint">
                        {d.checked_at
                          ? new Date(d.checked_at).toLocaleString()
                          : '—'}
                      </td>
                      <td>
                        <div className="row-actions">
                          <button
                            className="link"
                            disabled={checking === d.id}
                            onClick={() => void open(d)}
                          >
                            {checking === d.id ? 'Checking…' : 'Check records'}
                          </button>
                          {canEdit && (
                            <button
                              className="link danger"
                              onClick={() => void remove(d)}
                            >
                              Remove
                            </button>
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
        {domains && domains.length === 0 && (
          <p className="hint">No mail domains yet.</p>
        )}
        {canEdit && (
          <AddDomainForm
            providers={providers}
            onAdded={(c) => {
              setCheck(c)
              load()
            }}
          />
        )}
      </section>
      {check && (
        <RecordsCard
          key={check.domain.id}
          check={check}
          canEdit={canEdit}
          onChecked={(c) => {
            setCheck(c)
            load()
          }}
          onRecheck={() => void open(check.domain)}
        />
      )}
    </div>
  )
}

function OwnershipCard({
  value,
  isAdmin,
  onSaved,
}: {
  value: string | null
  isAdmin: boolean
  onSaved: (v: string) => void
}) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState('')
  const [error, setError] = useState<string | null>(null)

  async function save(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      const r = await api.saveMailSettings(draft)
      setEditing(false)
      onSaved(r.ownership)
    } catch (err) {
      setError(
        err instanceof ApiError && err.fields.ownership
          ? err.fields.ownership
          : message(err),
      )
    }
  }

  if (value === null) return null
  return (
    <section className="card">
      <h2>Purelymail account</h2>
      <p className="hint">
        Purelymail proves a domain is yours with a TXT record that is the same
        for every domain on your account. In Purelymail, open{' '}
        <strong>Domains → Add new domain</strong> and copy the ownership TXT
        value (it starts with{' '}
        <span className="mono">purelymail_ownership_proof=</span>).
      </p>
      {!editing && (
        <div className="actions">
          {value ? (
            <span className="mono">{value}</span>
          ) : (
            <span className="badge cert-pending">Not set</span>
          )}
          {isAdmin && (
            <button
              className="secondary small"
              onClick={() => {
                setDraft(value)
                setEditing(true)
              }}
            >
              {value ? 'Change' : 'Set ownership proof'}
            </button>
          )}
          {!isAdmin && !value && (
            <span className="hint">An administrator needs to set it.</span>
          )}
        </div>
      )}
      {editing && (
        <form className="actions wildcard-form" onSubmit={save}>
          <label className="grow">
            Ownership TXT value
            <input
              className="mono"
              autoFocus
              autoComplete="off"
              placeholder="purelymail_ownership_proof=…"
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
          </label>
          <button>Save</button>
          <button
            type="button"
            className="secondary"
            onClick={() => setEditing(false)}
          >
            Cancel
          </button>
        </form>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}

function AddDomainForm({
  providers,
  onAdded,
}: {
  providers: DNSProvider[]
  onAdded: (c: MailCheck) => void
}) {
  const [domain, setDomain] = useState('')
  const [provider, setProvider] = useState<number | ''>('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})

  useEffect(() => {
    if (providers.length === 1) setProvider(providers[0].id) // eslint-disable-line react-hooks/set-state-in-effect
  }, [providers])

  async function add(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setFields({})
    setBusy(true)
    try {
      onAdded(await api.addMailDomain(domain, Number(provider)))
      setDomain('')
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <form className="actions wildcard-form" onSubmit={add}>
        <label className="grow">
          Domain
          <input
            required
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
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
        <button disabled={busy || providers.length === 0}>
          <Mail size={16} aria-hidden="true" />{' '}
          {busy ? 'Checking…' : 'Add domain'}
        </button>
      </form>
      {providers.length === 0 && (
        <p className="hint">
          Add a Cloudflare DNS provider first, on the <a href="#/dns">DNS</a>{' '}
          page. Its token needs Zone → DNS → Edit on the domain’s zone.
        </p>
      )}
      {error && !Object.keys(fields).length && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <p className="hint">
        Adding a domain only checks its DNS; you choose what to change next.
      </p>
    </>
  )
}

function RecordsCard({
  check,
  canEdit,
  onChecked,
  onRecheck,
}: {
  check: MailCheck
  canEdit: boolean
  onChecked: (c: MailCheck) => void
  onRecheck: () => void
}) {
  const domain = check.domain.domain
  const [replace, setReplace] = useState<Set<string>>(new Set())
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<MailCheck['changes'] | null>(null)

  const missing = check.records.filter((r) => r.state === 'missing')
  const chosen = check.records.filter(
    (r) => r.state === 'conflict' && replace.has(r.key),
  )
  const toDelete = chosen.flatMap((r) => r.conflicts)
  const toAdd = missing.length + chosen.filter((r) => !r.present).length

  function toggle(key: string) {
    const next = new Set(replace)
    if (next.has(key)) next.delete(key)
    else next.add(key)
    setReplace(next)
  }

  async function apply() {
    if (
      toDelete.length > 0 &&
      !confirm(
        `Delete ${toDelete.length} record(s) from ${check.domain.zone_name} in Cloudflare?\n\n` +
          toDelete.map((r) => '• ' + describe(r, domain)).join('\n') +
          '\n\nThey are kept in the audit log, so they can be put back by hand.',
      )
    )
      return
    setError(null)
    setBusy(true)
    try {
      const c = await api.applyMailDomain(check.domain.id, [...replace])
      setResult(c.changes ?? [])
      setReplace(new Set())
      onChecked(c)
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  const failed = result?.filter((c) => c.error) ?? []
  const done = check.domain.status === 'ok'

  return (
    <section className="card">
      <div className="actions">
        <h2 className="grow">
          Purelymail records for <span className="mono">{domain}</span>
        </h2>
        <button className="secondary small" onClick={onRecheck}>
          <RefreshCw size={14} aria-hidden="true" /> Check again
        </button>
      </div>
      {result && result.length > 0 && failed.length === 0 && (
        <p className="success" role="status">
          Done: {result.filter((c) => c.action === 'create').length} added,{' '}
          {result.filter((c) => c.action === 'delete').length} deleted.
        </p>
      )}
      {failed.length > 0 && (
        <div className="error" role="alert">
          Some changes failed:
          <ul>
            {failed.map((c, i) => (
              <li key={i}>
                {c.action} {describe(c.record, domain)}: {c.error}
              </li>
            ))}
          </ul>
        </div>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="table-wrap">
        <table className="mail-records">
          <thead>
            <tr>
              <th>Record</th>
              <th>Type</th>
              <th>Name</th>
              <th>Value</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {check.records.map((r) => {
              const [text, cls] = recordState[r.state]
              return (
                <tr key={r.key}>
                  <td>{r.label}</td>
                  <td className="mono">{r.type}</td>
                  <td className="mono">{short(r.name, domain)}</td>
                  <td className="mono mail-value">
                    {r.priority != null && `${r.priority} `}
                    {r.content || '—'}
                  </td>
                  <td>
                    <span className={`badge ${cls}`}>{text}</span>
                    {r.state === 'conflict' && (
                      <div className="mail-conflict">
                        {r.note && <div className="hint">{r.note}</div>}
                        <ul className="perm-list">
                          {r.conflicts.map((c) => (
                            <li key={c.id} className="mono">
                              {describe(c, domain)}
                            </li>
                          ))}
                        </ul>
                        {canEdit && (
                          <label className="inline">
                            <input
                              type="checkbox"
                              checked={replace.has(r.key)}
                              onChange={() => toggle(r.key)}
                            />
                            Replace (delete{' '}
                            {r.conflicts.length === 1
                              ? 'it'
                              : `these ${r.conflicts.length}`}
                            )
                          </label>
                        )}
                      </div>
                    )}
                    {r.state === 'needs_value' && r.note && (
                      <div className="hint">{r.note}</div>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {canEdit && !done && (
        <div className="actions">
          <button
            disabled={busy || toAdd + toDelete.length === 0}
            onClick={() => void apply()}
          >
            {busy ? 'Updating Cloudflare…' : applyLabel(toAdd, toDelete.length)}
          </button>
          {toAdd + toDelete.length === 0 && (
            <span className="hint">
              Nothing to add. Tick “Replace” on the records that are in the way,
              or fix them in Cloudflare.
            </span>
          )}
        </div>
      )}
      {done ? (
        <p className="success">
          Every record Purelymail needs is in place. Finish adding the domain in
          Purelymail; it verifies the records within a few minutes to a few
          hours.
        </p>
      ) : (
        <p className="hint">
          Records are added as DNS only (not proxied) with automatic TTL.
        </p>
      )}
    </section>
  )
}
