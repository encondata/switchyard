import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, type Status, type User } from './api'

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

function Login({ onSignedIn }: { onSignedIn: (u: User) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onSignedIn(await api.login(username, password))
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h1>Sign in</h1>
      <label>
        Username
        <input
          autoComplete="username"
          autoFocus
          required
          value={username}
          onChange={(e) => setUsername(e.target.value)}
        />
      </label>
      <label>
        Password
        <input
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(e) => setPassword(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
    </form>
  )
}

function ChangePassword({
  user,
  onChanged,
  onCancel,
}: {
  user: User
  onChanged: (u: User) => void
  onCancel?: () => void
}) {
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (next !== confirm) {
      setError('The new passwords don’t match.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      onChanged(await api.changePassword(current, next))
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(false)
    }
  }

  return (
    <form className="card" onSubmit={submit}>
      <h1>Change password</h1>
      {user.must_change_password && (
        <p className="notice">
          You signed in with the default password. Choose a new one to continue.
        </p>
      )}
      <input type="hidden" autoComplete="username" value={user.username} />
      <label>
        Current password
        <input
          type="password"
          autoComplete="current-password"
          autoFocus
          required
          value={current}
          onChange={(e) => setCurrent(e.target.value)}
        />
      </label>
      <label>
        New password <span className="hint">(at least 8 characters)</span>
        <input
          type="password"
          autoComplete="new-password"
          required
          minLength={8}
          maxLength={72}
          value={next}
          onChange={(e) => setNext(e.target.value)}
        />
      </label>
      <label>
        Confirm new password
        <input
          type="password"
          autoComplete="new-password"
          required
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
        />
      </label>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      <div className="actions">
        <button disabled={busy}>{busy ? 'Saving…' : 'Change password'}</button>
        {onCancel && (
          <button type="button" className="secondary" onClick={onCancel}>
            Cancel
          </button>
        )}
      </div>
    </form>
  )
}

function Dashboard() {
  const [status, setStatus] = useState<Status | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .status()
      .then(setStatus)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  return (
    <section className="card wide">
      <h1>Status</h1>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!status && !error && <p>Checking…</p>}
      {status && (
        <dl>
          <dt>CPM version</dt>
          <dd>{status.version}</dd>
          <dt>Caddy admin API</dt>
          <dd>
            {status.caddy.reachable ? (
              <span className="ok">Reachable</span>
            ) : (
              <span className="bad">Not reachable</span>
            )}
            {status.caddy.socket && <code> {status.caddy.socket}</code>}
            {status.caddy.error && (
              <div className="hint">{status.caddy.error}</div>
            )}
          </dd>
        </dl>
      )}
      <p className="hint">
        Hosts, certificates and the rest of CPM arrive in phase 1.
      </p>
    </section>
  )
}

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [changing, setChanging] = useState(false)

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((err: unknown) => {
        if (!(err instanceof ApiError && err.status === 401)) console.error(err)
      })
      .finally(() => setLoading(false))
  }, [])

  async function signOut() {
    await api.logout().catch(() => undefined)
    setUser(null)
    setChanging(false)
  }

  let body
  if (loading) body = <p>Loading…</p>
  else if (!user) body = <Login onSignedIn={setUser} />
  else if (user.must_change_password || changing)
    body = (
      <ChangePassword
        user={user}
        onChanged={(u) => {
          setUser(u)
          setChanging(false)
        }}
        onCancel={
          user.must_change_password ? undefined : () => setChanging(false)
        }
      />
    )
  else body = <Dashboard />

  return (
    <>
      <header>
        <strong>CaddyProxyManager</strong>
        {user && (
          <nav>
            <span>{user.username}</span>
            {!user.must_change_password && (
              <button className="link" onClick={() => setChanging(true)}>
                Change password
              </button>
            )}
            <button className="link" onClick={signOut}>
              Sign out
            </button>
          </nav>
        )}
      </header>
      <main>{body}</main>
    </>
  )
}

export default App
