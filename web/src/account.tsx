import { useEffect, useState, type FormEvent } from 'react'
import qrcode from 'qrcode-generator'
import { api, ApiError, message, type TwoFAStatus, type User } from './api'

/** Renders an otpauth:// URI as an SVG QR code. */
function QRCode({ value }: { value: string }) {
  const qr = qrcode(0, 'M')
  qr.addData(value)
  qr.make()
  const n = qr.getModuleCount()
  const cells: string[] = []
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++)
      if (qr.isDark(r, c)) cells.push(`M${c} ${r}h1v1h-1z`)
  return (
    <svg
      className="qr"
      viewBox={`-2 -2 ${n + 4} ${n + 4}`}
      role="img"
      aria-label="QR code for your authenticator app"
    >
      <rect x={-2} y={-2} width={n + 4} height={n + 4} fill="#fff" />
      <path d={cells.join('')} fill="#000" />
    </svg>
  )
}

/** Set up two-factor sign-in: scan, confirm a code, save backup codes. */
export function TwoFASetup({ onDone }: { onDone: () => void }) {
  const [setup, setSetup] = useState<{ secret: string; uri: string } | null>(
    null,
  )
  const [code, setCode] = useState('')
  const [codes, setCodes] = useState<string[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .twoFABegin()
      .then(setSetup)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  async function confirm(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      setCodes((await api.twoFAConfirm(code)).backup_codes)
    } catch (err) {
      setError(
        err instanceof ApiError && err.fields.code
          ? err.fields.code
          : message(err),
      )
    }
  }

  if (codes)
    return (
      <div className="stack-tight">
        <h2>Save your backup codes</h2>
        <p>
          Two-factor sign-in is on. If you lose your phone, sign in with one of
          these codes instead of an app code. Each works once. They won’t be
          shown again.
        </p>
        <ul className="backup-codes mono">
          {codes.map((c) => (
            <li key={c}>{c}</li>
          ))}
        </ul>
        <div className="actions">
          <button
            type="button"
            className="secondary"
            onClick={() =>
              void navigator.clipboard?.writeText(codes.join('\n'))
            }
          >
            Copy codes
          </button>
          <button type="button" onClick={onDone}>
            I’ve saved them
          </button>
        </div>
      </div>
    )

  return (
    <form className="stack-tight" onSubmit={confirm}>
      <h2>Set up two-factor sign-in</h2>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!setup && !error && <p>Preparing…</p>}
      {setup && (
        <>
          <p>
            1. Scan this with an authenticator app (1Password, Google
            Authenticator, Authy, …).
          </p>
          <QRCode value={setup.uri} />
          <p className="hint">
            Can’t scan? Enter this key instead:{' '}
            <code className="secret">{setup.secret}</code>
          </p>
          <label>
            2. Enter the 6-digit code the app shows
            <input
              className="mono code-input"
              inputMode="numeric"
              autoComplete="one-time-code"
              required
              autoFocus
              value={code}
              onChange={(e) => setCode(e.target.value)}
            />
          </label>
          <div className="actions">
            <button>Turn on</button>
          </div>
        </>
      )}
    </form>
  )
}

/** Shown when an admin requires 2FA and this user hasn't set it up. */
export function EnrollRequired({ onDone }: { onDone: () => void }) {
  return (
    <section className="card narrow-wide">
      <p className="notice">
        Your admin requires two-factor sign-in. Set it up to continue.
      </p>
      <TwoFASetup onDone={onDone} />
    </section>
  )
}

export function AccountPage({
  user,
  onChangePassword,
  onChanged,
}: {
  user: User
  onChangePassword: () => void
  onChanged: () => void
}) {
  const [status, setStatus] = useState<TwoFAStatus | null>(null)
  const [settingUp, setSettingUp] = useState(false)
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)

  function load() {
    api
      .twoFA()
      .then(setStatus)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function disable(e: FormEvent) {
    e.preventDefault()
    setError(null)
    try {
      await api.twoFADisable(password)
      setPassword('')
      load()
      onChanged()
    } catch (err) {
      setError(message(err))
    }
  }

  return (
    <section className="card narrow-wide">
      <h1>Your account</h1>
      <dl>
        <dt>Username</dt>
        <dd>{user.username}</dd>
        <dt>Role</dt>
        <dd>{user.role}</dd>
        <dt>Password</dt>
        <dd>
          <button className="link" onClick={onChangePassword}>
            Change password
          </button>
        </dd>
      </dl>
      <h2>Two-factor sign-in</h2>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {status && !status.available && !status.enabled && (
        <p className="hint">
          Not available: the server has no CPM_SECRET_KEY to store secrets
          encrypted.
        </p>
      )}
      {status && status.enabled && (
        <>
          <p>
            <span className="ok">On.</span> {status.backup_codes_left} backup
            code(s) left.
          </p>
          {status.required ? (
            <p className="hint">Required for everyone by your admin.</p>
          ) : (
            <form className="actions" onSubmit={disable}>
              <input
                type="password"
                placeholder="Your password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
              <button className="secondary">Turn off</button>
            </form>
          )}
        </>
      )}
      {status && !status.enabled && status.available && !settingUp && (
        <div>
          <p>Off. Add a code from your phone to every sign-in.</p>
          <button onClick={() => setSettingUp(true)}>Set up</button>
        </div>
      )}
      {settingUp && (
        <TwoFASetup
          onDone={() => {
            setSettingUp(false)
            load()
            onChanged()
          }}
        />
      )}
    </section>
  )
}
