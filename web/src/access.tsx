import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, message, type AccessPolicy, type NeverBan } from './api'
import { PolicyBadge } from './hosts'

type Draft = Pick<
  AccessPolicy,
  'id' | 'name' | 'mode' | 'response' | 'rules' | 'notes'
>

const blank: Draft = {
  id: 0,
  name: '',
  mode: 'allow_only',
  response: '403',
  rules: [],
  notes: '',
}

function PolicyForm({
  initial,
  onDone,
}: {
  initial: Draft
  onDone: (changed: boolean) => void
}) {
  const [p, setP] = useState<Draft>(initial)
  const [rules, setRules] = useState(initial.rules.join('\n'))
  const [error, setError] = useState<string | null>(null)
  const [fields, setFields] = useState<Record<string, string>>({})

  async function submit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setFields({})
    try {
      await api.savePolicy({
        ...p,
        rules: rules.split(/[\s,]+/).filter(Boolean),
      })
      onDone(true)
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  return (
    <form className="folder-form" onSubmit={submit}>
      <h2>{p.id ? `Edit “${initial.name}”` : 'New policy'}</h2>
      <label>
        Name
        <input
          autoFocus
          required
          value={p.name}
          placeholder="Office only"
          onChange={(e) => setP({ ...p, name: e.target.value })}
        />
        {fields.name && <span className="field-error">{fields.name}</span>}
      </label>
      <fieldset>
        <legend>Mode</legend>
        <label className="inline">
          <input
            type="radio"
            checked={p.mode === 'allow_only'}
            onChange={() => setP({ ...p, mode: 'allow_only' })}
          />
          <span>
            <strong>Allow only</strong> these addresses; block everyone else
          </span>
        </label>
        <label className="inline">
          <input
            type="radio"
            checked={p.mode === 'deny'}
            onChange={() => setP({ ...p, mode: 'deny' })}
          />
          <span>
            <strong>Deny</strong> these addresses; allow everyone else
          </span>
        </label>
      </fieldset>
      <label>
        Addresses{' '}
        <span className="hint">(IPs or CIDR ranges, one per line)</span>
        <textarea
          rows={5}
          required
          className="mono"
          placeholder={'192.168.1.0/24\n10.0.0.5\n2001:db8::/32'}
          value={rules}
          onChange={(e) => setRules(e.target.value)}
        />
        {fields.rules && <span className="field-error">{fields.rules}</span>}
      </label>
      <label>
        Blocked visitors get
        <select
          value={p.response}
          onChange={(e) =>
            setP({ ...p, response: e.target.value as Draft['response'] })
          }
        >
          <option value="403">A 403 “Access denied” page</option>
          <option value="abort">Nothing — the connection is dropped</option>
        </select>
      </label>
      <label>
        Notes
        <textarea
          rows={2}
          value={p.notes}
          onChange={(e) => setP({ ...p, notes: e.target.value })}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        <button>Save policy</button>
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

export function AccessPage({
  canEdit,
  onChanged,
}: {
  canEdit: boolean
  onChanged: () => void
}) {
  const [policies, setPolicies] = useState<AccessPolicy[] | null>(null)
  const [never, setNever] = useState<NeverBan[]>([])
  const [myIp, setMyIp] = useState<string | null>(null)
  const [editing, setEditing] = useState<Draft | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [nbCidr, setNbCidr] = useState('')
  const [nbNote, setNbNote] = useState('')
  const [nbError, setNbError] = useState<string | null>(null)

  function load() {
    Promise.all([api.policies(), api.neverBan(), api.whoami()])
      .then(([p, n, w]) => {
        setPolicies(p)
        setNever(n)
        setMyIp(w.ip)
      })
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function removePolicy(p: AccessPolicy) {
    if (!confirm(`Delete the policy “${p.name}”?`)) return
    setError(null)
    try {
      await api.deletePolicy(p.id)
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  async function addNever(e: FormEvent) {
    e.preventDefault()
    setNbError(null)
    try {
      await api.addNeverBan(nbCidr, nbNote)
      setNbCidr('')
      setNbNote('')
      load()
      onChanged()
    } catch (err) {
      setNbError(
        message(err) === 'Fix the highlighted fields.' &&
          err instanceof ApiError
          ? Object.values(err.fields).join(' ')
          : message(err),
      )
    }
  }

  async function removeNever(cidr: string) {
    if (!confirm(`Remove ${cidr} from the never-block list?`)) return
    try {
      await api.deleteNeverBan(cidr)
      load()
      onChanged()
    } catch (err) {
      setNbError(message(err))
    }
  }

  return (
    <div className="stack">
      <section className="card">
        {editing ? (
          <PolicyForm
            initial={editing}
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
              <h1>Access policies</h1>
              {canEdit && (
                <button onClick={() => setEditing(blank)}>New policy</button>
              )}
            </div>
            <p className="hint">
              Attach policies to a folder (every host inside gets them) or to a
              single host. Rules are checked in this order: never-block list,
              then deny policies, then allow-only policies. These rules apply to
              sites served by Caddy, not to this CPM page.
            </p>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            {policies?.length === 0 && <p>No policies yet.</p>}
            {policies && policies.length > 0 && (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Policy</th>
                      <th>Addresses</th>
                      <th>Blocked get</th>
                      <th>Used by</th>
                      {canEdit && <th aria-label="Actions" />}
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p) => (
                      <tr key={p.id}>
                        <td>
                          <PolicyBadge p={p} />
                          <div className="hint">
                            {p.mode === 'allow_only' ? 'Allow only' : 'Deny'}
                          </div>
                        </td>
                        <td className="mono">
                          {p.rules.slice(0, 4).join(', ')}
                          {p.rules.length > 4 && ` +${p.rules.length - 4} more`}
                        </td>
                        <td>
                          {p.response === 'abort' ? 'Dropped' : '403 page'}
                        </td>
                        <td>
                          {p.folder_count} folder(s), {p.host_count} host(s)
                        </td>
                        {canEdit && (
                          <td>
                            <div className="row-actions">
                              <button
                                className="link"
                                onClick={() => setEditing(p)}
                              >
                                Edit
                              </button>
                              <button
                                className="link danger"
                                onClick={() => removePolicy(p)}
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
          </>
        )}
      </section>

      <section className="card">
        <h1>Never block</h1>
        <p className="hint">
          Addresses here get through every rule, on every host, even if a policy
          or (later) the honeypot would block them. Add your own office or VPN
          addresses so you can’t lock yourself out.
        </p>
        {nbError && (
          <p className="error" role="alert">
            {nbError}
          </p>
        )}
        {never.length > 0 && (
          <ul className="never-list">
            {never.map((n) => (
              <li key={n.cidr}>
                <code>{n.cidr}</code>
                {n.note && <span className="hint"> — {n.note}</span>}
                {canEdit && (
                  <button
                    className="link danger"
                    onClick={() => removeNever(n.cidr)}
                  >
                    Remove
                  </button>
                )}
              </li>
            ))}
          </ul>
        )}
        {canEdit && (
          <form className="actions" onSubmit={addNever}>
            <input
              required
              className="mono"
              placeholder="203.0.113.10 or 192.168.1.0/24"
              value={nbCidr}
              onChange={(e) => setNbCidr(e.target.value)}
            />
            <input
              className="grow"
              placeholder="Note (optional)"
              value={nbNote}
              onChange={(e) => setNbNote(e.target.value)}
            />
            <button>Add</button>
            {myIp && (
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setNbCidr(myIp)
                  setNbNote('Added from CPM')
                }}
                title="The address CPM sees for you. Behind Docker Desktop or NAT this may be a gateway address."
              >
                Use my IP ({myIp})
              </button>
            )}
          </form>
        )}
      </section>
    </div>
  )
}
