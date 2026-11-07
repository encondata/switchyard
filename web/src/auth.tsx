import { useState, type FormEvent } from 'react'
import { api, ApiError, message, type User } from './api'

export function Login({ onSignedIn }: { onSignedIn: (u: User) => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [code, setCode] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)

  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError(null)
    try {
      if (challenge) {
        onSignedIn(await api.loginTOTP(challenge, code))
        return
      }
      const r = await api.login(username, password)
      if ('totp_required' in r) {
        setChallenge(r.challenge)
        setPassword('')
      } else onSignedIn(r)
    } catch (err) {
      setError(message(err))
      if (err instanceof ApiError && err.code === 'challenge_expired') {
        setChallenge(null)
        setCode('')
      }
    } finally {
      setBusy(false)
    }
  }

  if (challenge)
    return (
      <form className="card narrow" onSubmit={submit}>
        <h1>Two-factor sign-in</h1>
        <label>
          Code from your authenticator app
          <input
            className="mono code-input"
            inputMode="numeric"
            autoComplete="one-time-code"
            autoFocus
            required
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <span className="hint">
            Lost your phone? Enter one of your backup codes.
          </span>
        </label>
        {error && (
          <p className="error" role="alert">
            {error}
          </p>
        )}
        <button disabled={busy}>{busy ? 'Checking…' : 'Sign in'}</button>
        <button
          type="button"
          className="link"
          onClick={() => {
            setChallenge(null)
            setCode('')
            setError(null)
          }}
        >
          Back
        </button>
      </form>
    )

  return (
    <form className="card narrow" onSubmit={submit}>
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

export function ChangePassword({
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
    <form className="card narrow" onSubmit={submit}>
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
