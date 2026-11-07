import { Fragment, useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, message, type AuditEntry, type User } from './api'

const roles: { value: User['role']; label: string; hint: string }[] = [
  {
    value: 'admin',
    label: 'Admin',
    hint: 'everything, including users and DNS credentials',
  },
  { value: 'editor', label: 'Editor', hint: 'hosts, folders, policies, apply' },
  { value: 'viewer', label: 'Viewer', hint: 'read only' },
]

export function UsersPage({ me }: { me: User }) {
  const [users, setUsers] = useState<User[] | null>(null)
  const [require2FA, setRequire2FA] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)
  const [adding, setAdding] = useState(false)
  const [nu, setNu] = useState({
    username: '',
    role: 'editor' as User['role'],
    password: '',
  })
  const [fields, setFields] = useState<Record<string, string>>({})

  function load() {
    Promise.all([api.users(), api.settings()])
      .then(([u, s]) => {
        setUsers(u)
        setRequire2FA(s.require_2fa)
      })
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function run(fn: () => Promise<unknown>, done: string) {
    setError(null)
    setInfo(null)
    try {
      await fn()
      setInfo(done)
      load()
    } catch (err) {
      setError(message(err))
    }
  }

  async function add(e: FormEvent) {
    e.preventDefault()
    setFields({})
    setError(null)
    try {
      await api.createUser(nu.username, nu.role, nu.password)
      setInfo(
        `Added ${nu.username}. Give them the temporary password; they’ll choose their own at first sign-in.`,
      )
      setNu({ username: '', role: 'editor', password: '' })
      setAdding(false)
      load()
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError) setFields(err.fields)
    }
  }

  function resetPassword(u: User) {
    const pw = prompt(
      `New temporary password for ${u.username} (at least 8 characters). They’ll be signed out and must change it at next sign-in.`,
    )
    if (pw)
      void run(
        () => api.resetUserPassword(u.id, pw),
        `Password reset for ${u.username}.`,
      )
  }

  return (
    <div className="stack">
      <section className="card">
        <div className="toolbar">
          <h1>Users</h1>
          <button onClick={() => setAdding(!adding)}>
            {adding ? 'Cancel' : 'Add user'}
          </button>
        </div>
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
        {adding && (
          <form className="folder-form" onSubmit={add}>
            <label>
              Username
              <input
                required
                autoFocus
                value={nu.username}
                onChange={(e) => setNu({ ...nu, username: e.target.value })}
              />
              {fields.username && (
                <span className="field-error">{fields.username}</span>
              )}
            </label>
            <label>
              Role
              <select
                value={nu.role}
                onChange={(e) =>
                  setNu({ ...nu, role: e.target.value as User['role'] })
                }
              >
                {roles.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label} — {r.hint}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Temporary password
              <input
                required
                minLength={8}
                autoComplete="new-password"
                value={nu.password}
                onChange={(e) => setNu({ ...nu, password: e.target.value })}
              />
              {fields.password && (
                <span className="field-error">{fields.password}</span>
              )}
            </label>
            <div className="actions">
              <button>Add user</button>
            </div>
          </form>
        )}
        {users && (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>User</th>
                  <th>Role</th>
                  <th>2FA</th>
                  <th>Status</th>
                  <th aria-label="Actions" />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const self = u.id === me.id
                  return (
                    <tr key={u.id} className={u.disabled ? 'disabled' : ''}>
                      <td>
                        {u.username}{' '}
                        {self && <span className="hint">(you)</span>}
                        {u.must_change_password && (
                          <div className="hint">must change password</div>
                        )}
                      </td>
                      <td>
                        <select
                          aria-label={`Role of ${u.username}`}
                          value={u.role}
                          disabled={self}
                          onChange={(e) =>
                            run(
                              () =>
                                api.updateUser(
                                  u.id,
                                  e.target.value as User['role'],
                                  u.disabled,
                                ),
                              `${u.username} is now ${e.target.value}.`,
                            )
                          }
                        >
                          {roles.map((r) => (
                            <option key={r.value} value={r.value}>
                              {r.label}
                            </option>
                          ))}
                        </select>
                      </td>
                      <td>
                        {u.totp_enabled ? (
                          <span className="ok">On</span>
                        ) : (
                          'Off'
                        )}
                      </td>
                      <td>
                        {u.disabled ? (
                          <span className="bad">Disabled</span>
                        ) : (
                          'Active'
                        )}
                      </td>
                      <td>
                        {!self && (
                          <div className="row-actions">
                            <button
                              className="link"
                              onClick={() =>
                                run(
                                  () =>
                                    api.updateUser(u.id, u.role, !u.disabled),
                                  `${u.username} ${u.disabled ? 'enabled' : 'disabled'}.`,
                                )
                              }
                            >
                              {u.disabled ? 'Enable' : 'Disable'}
                            </button>
                            <button
                              className="link"
                              onClick={() => resetPassword(u)}
                            >
                              Reset password
                            </button>
                            {u.totp_enabled && (
                              <button
                                className="link"
                                onClick={() => {
                                  if (
                                    confirm(
                                      `Turn off two-factor sign-in for ${u.username}? Use this if they lost their phone and backup codes.`,
                                    )
                                  )
                                    void run(
                                      () => api.resetUser2FA(u.id),
                                      `2FA reset for ${u.username}.`,
                                    )
                                }}
                              >
                                Reset 2FA
                              </button>
                            )}
                            <button
                              className="link danger"
                              onClick={() => {
                                if (confirm(`Delete ${u.username}?`))
                                  void run(
                                    () => api.deleteUser(u.id),
                                    `${u.username} deleted.`,
                                  )
                              }}
                            >
                              Delete
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

      <section className="card">
        <h1>Sign-in policy</h1>
        <label className="inline">
          <input
            type="checkbox"
            checked={require2FA}
            onChange={(e) =>
              run(
                () => api.saveSettings(e.target.checked),
                e.target.checked
                  ? 'Two-factor sign-in is now required. Users without it must set it up at their next request.'
                  : 'Two-factor sign-in is now optional.',
              )
            }
          />
          Require two-factor sign-in for everyone
        </label>
        <p className="hint">
          Turn it on for your own account first (Account page). Failed sign-ins
          are limited to 5 per username and 10 per IP address every 15 minutes.
        </p>
      </section>
    </div>
  )
}

function pretty(s: string): string {
  if (!s) return ''
  try {
    return JSON.stringify(JSON.parse(s), null, 2)
  } catch {
    return s
  }
}

export function AuditPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [done, setDone] = useState(false)
  const [entity, setEntity] = useState('')
  const [user, setUser] = useState('')
  const [open, setOpen] = useState<number | null>(null)
  const [error, setError] = useState<string | null>(null)

  function load(reset: boolean) {
    const before = reset ? undefined : entries[entries.length - 1]?.id
    api
      .audit({ before, entity, user })
      .then((page) => {
        setEntries(reset ? page : [...entries, ...page])
        setDone(page.length < 100)
      })
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(() => load(true), [entity, user]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <section className="card">
      <div className="toolbar">
        <h1>Audit log</h1>
        <select
          aria-label="Filter by type"
          value={entity}
          onChange={(e) => setEntity(e.target.value)}
        >
          <option value="">All changes</option>
          <option value="host">Hosts</option>
          <option value="folder">Folders</option>
          <option value="access_policy">Access policies</option>
          <option value="never_ban">Never-block list</option>
          <option value="dns_provider">DNS providers</option>
          <option value="config">Applies</option>
          <option value="user">Users</option>
          <option value="session">Sign-ins</option>
          <option value="setting">Settings</option>
        </select>
        <input
          className="search"
          placeholder="Filter by user"
          value={user}
          onChange={(e) => setUser(e.target.value.trim())}
        />
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Who</th>
              <th>What</th>
              <th aria-label="Details" />
            </tr>
          </thead>
          <tbody>
            {entries.map((e) => (
              <Fragment key={e.id}>
                <tr>
                  <td>
                    {new Date(
                      e.at + (e.at.endsWith('Z') ? '' : 'Z'),
                    ).toLocaleString()}
                  </td>
                  <td>{e.username}</td>
                  <td>
                    {e.action.replace(/_/g, ' ')} {e.entity.replace(/_/g, ' ')}
                    {e.entity_id && e.entity_id !== '0' && ` #${e.entity_id}`}
                  </td>
                  <td>
                    {(e.before || e.after) && (
                      <button
                        className="link"
                        onClick={() => setOpen(open === e.id ? null : e.id)}
                      >
                        {open === e.id ? 'Hide' : 'Details'}
                      </button>
                    )}
                  </td>
                </tr>
                {open === e.id && (
                  <tr>
                    <td colSpan={4}>
                      <div className="audit-diff">
                        {e.before && (
                          <div>
                            <div className="hint">Before</div>
                            <pre className="diff">{pretty(e.before)}</pre>
                          </div>
                        )}
                        {e.after && (
                          <div>
                            <div className="hint">After</div>
                            <pre className="diff">{pretty(e.after)}</pre>
                          </div>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
      {!done && entries.length > 0 && (
        <button className="secondary" onClick={() => load(false)}>
          Load older
        </button>
      )}
    </section>
  )
}
