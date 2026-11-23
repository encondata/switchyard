import { useState, type FormEvent } from 'react'
import { api, ApiError, message, type AuthConfig, type User } from './api'
import { ssoError } from './sso'
import { SsoButton } from './sso-ui'

export function Login({
  onSignedIn,
  config,
}: {
  onSignedIn: (u: User) => void
  config: AuthConfig | null
}) {
  const params = new URLSearchParams(location.search)
  const errorCode = params.get('error')
  const sso = !!config?.oidc.enabled
  // With HackSpaceLabs sign-in doing the work, the local form is for administrators when it is down.
  const [showLocal, setShowLocal] = useState(
    !sso ||
      !config?.oidc.auto_redirect ||
      params.has('local') ||
      errorCode === 'sso_unavailable',
  )
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
      {errorCode && (
        <p className="error" role="alert">
          {ssoError(errorCode)}
        </p>
      )}
      {sso && (
        <>
          <SsoButton />
          {errorCode === 'no_access' && (
            <a
              className="link"
              href="/api/auth/oidc/login?prompt=login&next=%2F"
            >
              Use a different HackSpaceLabs account
            </a>
          )}
        </>
      )}
      {sso && !showLocal && (
        <button
          type="button"
          className="link"
          onClick={() => setShowLocal(true)}
        >
          Use a local account
        </button>
      )}
      {sso && showLocal && (
        <div className="divider">or with a local account</div>
      )}
      {showLocal && (
        <LocalFields
          username={username}
          password={password}
          setUsername={setUsername}
          setPassword={setPassword}
          autoFocus={!sso}
        />
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {showLocal && (
        <button disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}</button>
      )}
    </form>
  )
}

function LocalFields(p: {
  username: string
  password: string
  setUsername: (v: string) => void
  setPassword: (v: string) => void
  autoFocus: boolean
}) {
  return (
    <>
      <label>
        Username
        <input
          autoComplete="username"
          autoFocus={p.autoFocus}
          required
          value={p.username}
          onChange={(e) => p.setUsername(e.target.value)}
        />
      </label>
      <label>
        Password
        <input
          type="password"
          autoComplete="current-password"
          required
          value={p.password}
          onChange={(e) => p.setPassword(e.target.value)}
        />
      </label>
    </>
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
