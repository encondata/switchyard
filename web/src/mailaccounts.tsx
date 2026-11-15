import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Check, Copy, Eye, EyeOff, RefreshCw, Wand2 } from 'lucide-react'
import {
  api,
  ApiError,
  message,
  type MailAccount,
  type MailAccountResult,
  type MailAccounts,
  type MailDomain,
} from './api'

const pwChars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'

/** A random 24-character password (no look-alike characters). */
function generatePassword(length = 24): string {
  const out: string[] = []
  const buf = new Uint8Array(64)
  while (out.length < length) {
    crypto.getRandomValues(buf)
    for (const b of buf) {
      // 57 characters: skip values that would bias the choice.
      if (b < 228 && out.length < length) out.push(pwChars[b % pwChars.length])
    }
  }
  return out.join('')
}

/** A password field with Generate, for a new password. */
function PasswordInput({
  value,
  onChange,
  id,
  error,
}: {
  value: string
  onChange: (v: string) => void
  id: string
  error?: string
}) {
  return (
    <div className="pw-input">
      <input
        id={id}
        className="mono"
        type="text"
        autoComplete="new-password"
        spellCheck={false}
        value={value}
        placeholder="At least 12 characters"
        aria-invalid={!!error}
        onChange={(e) => onChange(e.target.value)}
      />
      <button
        type="button"
        className="secondary small"
        onClick={() => onChange(generatePassword())}
      >
        <Wand2 size={14} aria-hidden="true" /> Generate
      </button>
    </div>
  )
}

/** A password shown on request (audited), with Copy. */
function SecretValue({
  load,
  canSee,
}: {
  load: () => Promise<string>
  canSee: boolean
}) {
  const [value, setValue] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function get(): Promise<string | null> {
    if (value !== null) return value
    try {
      const v = await load()
      setError(null)
      return v
    } catch (err) {
      setError(message(err))
      return null
    }
  }
  async function toggle() {
    if (value !== null) return setValue(null)
    setValue(await get())
  }
  async function copy() {
    const v = await get()
    if (v === null) return
    await navigator.clipboard.writeText(v)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <span className="pw-value">
      <code className="mono">{value ?? '••••••••••••'}</code>
      {canSee && (
        <>
          <button
            type="button"
            className="icon-btn"
            title={value !== null ? 'Hide' : 'Show'}
            aria-label={value !== null ? 'Hide password' : 'Show password'}
            onClick={() => void toggle()}
          >
            {value !== null ? (
              <EyeOff size={15} aria-hidden="true" />
            ) : (
              <Eye size={15} aria-hidden="true" />
            )}
          </button>
          <button
            type="button"
            className="icon-btn"
            title={copied ? 'Copied' : 'Copy'}
            aria-label="Copy password"
            onClick={() => void copy()}
          >
            {copied ? (
              <Check size={15} aria-hidden="true" />
            ) : (
              <Copy size={15} aria-hidden="true" />
            )}
          </button>
        </>
      )}
      {error && <span className="error">{error}</span>}
    </span>
  )
}

/**
 * A domain's email accounts at Purelymail. They share the domain's password
 * unless one has its own; passwords are kept here so they can be shown again.
 */
export function AccountsCard({
  domain,
  canEdit,
  onChanged,
}: {
  domain: MailDomain
  canEdit: boolean
  onChanged: () => void
}) {
  const [data, setData] = useState<MailAccounts | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<MailAccountResult[] | null>(null)
  const [failed, setFailed] = useState<{ address: string; error: string }[]>([])
  const [busy, setBusy] = useState<string | null>(null)
  // Bumped when a password changes, so shown values are fetched again.
  const [rev, setRev] = useState(0)

  async function load() {
    setLoading(true)
    try {
      setData(await api.mailAccounts(domain.id))
      setError(null)
    } catch (err) {
      setError(message(err))
    } finally {
      setLoading(false)
    }
  }
  const card = useRef<HTMLElement>(null)
  // The card is keyed by domain, so this runs once per domain.
  useEffect(() => {
    card.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
    api
      .mailAccounts(domain.id)
      .then(setData)
      .catch((err: unknown) => setError(message(err)))
  }, [domain.id])

  function update(v: MailAccounts) {
    setData(v)
    onChanged()
  }

  async function add(names: string[], password?: string, takeOver = false) {
    setError(null)
    setBusy('add')
    try {
      const r = await api.addMailAccounts(domain.id, {
        names,
        password: password || undefined,
        take_over: takeOver || undefined,
      })
      setResults(r.results)
      update(r)
      return r.results.every((x) => !x.error)
    } catch (err) {
      setError(message(err))
      return false
    } finally {
      setBusy(null)
    }
  }

  async function remove(a: MailAccount) {
    if (
      !confirm(
        `Delete ${a.address}?\n\nThis deletes the mailbox at Purelymail with all its mail, and its saved password here. It can't be undone.`,
      )
    )
      return
    setError(null)
    setBusy(`del-${a.id}`)
    try {
      await api.deleteMailAccount(a.id)
      await load()
      onChanged()
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(null)
    }
  }

  async function resetToShared(a: MailAccount) {
    if (
      !confirm(
        `Put ${a.address} back on the shared password? Its password changes at Purelymail.`,
      )
    )
      return
    setError(null)
    setBusy(`pw-${a.id}`)
    try {
      update(await api.setMailAccountPassword(a.id, { use_domain: true }))
      setRev((n) => n + 1)
    } catch (err) {
      setError(message(err))
    } finally {
      setBusy(null)
    }
  }

  const d = data?.domain ?? domain
  const missing = (data?.defaults ?? []).filter(
    (n) => !data?.accounts.some((a) => a.local_part === n),
  )
  const canCreate = canEdit && !!data?.key_set
  const sharedCount = data?.accounts.filter((a) => !a.own_password).length ?? 0

  return (
    <section className="card" ref={card}>
      <div className="actions">
        <h2 className="grow">
          Email accounts for <span className="mono">{d.domain}</span>
        </h2>
        <button
          className="secondary small"
          disabled={loading}
          onClick={() => void load()}
        >
          <RefreshCw size={14} aria-hidden="true" /> Refresh
        </button>
      </div>
      <p className="hint">
        Mailboxes at Purelymail. Sign in with the full address. Incoming: IMAP{' '}
        <span className="mono">imap.purelymail.com</span> port 993 (SSL).
        Sending: SMTP <span className="mono">smtp.purelymail.com</span> port 465
        (SSL) or 587 (STARTTLS).
      </p>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {data && !data.key_set && (
        <p className="hint">
          Add a Purelymail API key above to create and change accounts.
        </p>
      )}
      {data?.error && (
        <p className="error" role="alert">
          Couldn’t ask Purelymail: {data.error}
        </p>
      )}

      {data && (
        <SharedPassword
          key={`${d.id}-${rev}`}
          domain={d}
          canEdit={canEdit}
          canChange={canEdit && (sharedCount === 0 || data.key_set)}
          sharedCount={sharedCount}
          onSaved={(v, f) => {
            update(v)
            setFailed(f)
            setRev((n) => n + 1)
          }}
        />
      )}
      {failed.length > 0 && (
        <div className="error" role="alert">
          Purelymail didn’t change these, so they keep the old password (now as
          their own):
          <ul>
            {failed.map((f) => (
              <li key={f.address}>
                <span className="mono">{f.address}</span>: {f.error}
              </li>
            ))}
          </ul>
        </div>
      )}

      {data && data.accounts.length > 0 && (
        <div className="table-wrap">
          <table className="mail-accounts">
            <thead>
              <tr>
                <th>Address</th>
                <th>Password</th>
                <th>At Purelymail</th>
                {canEdit && <th />}
              </tr>
            </thead>
            <tbody>
              {data.accounts.map((a) => (
                <AccountRow
                  key={`${a.id}-${rev}`}
                  account={a}
                  canEdit={canEdit}
                  canChange={canEdit && data.key_set}
                  busy={busy}
                  sharedSet={d.password_set}
                  onRemove={() => void remove(a)}
                  onUseShared={() => void resetToShared(a)}
                  onOwnSaved={(v) => {
                    update(v)
                    setRev((n) => n + 1)
                  }}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
      {data && data.accounts.length === 0 && (
        <p className="hint">No accounts yet.</p>
      )}

      {results && results.some((r) => r.error) && (
        <div className="error" role="alert">
          Not added:
          <ul>
            {results
              .filter((r) => r.error)
              .map((r) => (
                <li key={r.name}>
                  <span className="mono">{r.address ?? r.name}</span>: {r.error}
                </li>
              ))}
          </ul>
        </div>
      )}
      {results && results.length > 0 && results.every((r) => !r.error) && (
        <p className="success" role="status">
          Added {results.map((r) => r.address).join(', ')}.
        </p>
      )}

      {canCreate && (
        <AddAccounts
          domain={d}
          missing={missing}
          busy={busy === 'add'}
          onAdd={add}
        />
      )}

      {data && data.others.length > 0 && (
        <div className="pm-others">
          <h3>Also at Purelymail, not managed here</h3>
          <p className="hint">
            Made at Purelymail directly, so Switchyard doesn’t know their
            passwords. Managing one here sets its password to the shared one.
          </p>
          <ul className="perm-list">
            {data.others.map((o) => (
              <li key={o}>
                <span className="mono">{o}</span>
                {canCreate && d.password_set && (
                  <button
                    className="link"
                    disabled={busy === 'add'}
                    onClick={() => {
                      if (
                        confirm(
                          `Manage ${o} here? Its password changes at Purelymail to ${d.domain}’s shared password, so anything signed in with the old one has to sign in again.`,
                        )
                      )
                        void add([o.split('@')[0]], undefined, true)
                    }}
                  >
                    Manage here
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}

function SharedPassword({
  domain,
  canEdit,
  canChange,
  sharedCount,
  onSaved,
}: {
  domain: MailDomain
  canEdit: boolean
  canChange: boolean
  sharedCount: number
  onSaved: (
    v: MailAccounts,
    failed: { address: string; error: string }[],
  ) => void
}) {
  const [editing, setEditing] = useState(!domain.password_set)
  const [pw, setPw] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function save(e: FormEvent) {
    e.preventDefault()
    if (
      domain.password_set &&
      sharedCount > 0 &&
      !confirm(
        `Change the password of ${sharedCount} account(s) at Purelymail? Anything signed in with the old password has to sign in again.`,
      )
    )
      return
    setBusy(true)
    setError(null)
    try {
      const r = await api.setMailDomainPassword(domain.id, pw)
      onSaved(r, r.failed)
      setEditing(false)
      setPw('')
    } catch (err) {
      setError(
        err instanceof ApiError && err.fields.password
          ? err.fields.password
          : message(err),
      )
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mail-shared">
      <div>
        <h3>Shared password</h3>
        <p className="hint">
          Every account on {domain.domain} uses it unless it has its own.
        </p>
      </div>
      {domain.password_set && !editing && (
        <div className="actions">
          <SecretValue
            canSee={canEdit}
            load={() =>
              api.revealMailDomainPassword(domain.id).then((r) => r.password)
            }
          />
          {canChange && (
            <button
              className="secondary small"
              onClick={() => setEditing(true)}
            >
              Change
            </button>
          )}
        </div>
      )}
      {!domain.password_set && !canEdit && <p className="hint">Not set yet.</p>}
      {editing && canEdit && (
        <form className="pw-form" onSubmit={(e) => void save(e)}>
          <label htmlFor={`shared-${domain.id}`}>
            {domain.password_set
              ? 'New shared password'
              : 'Set the shared password'}
          </label>
          <PasswordInput
            id={`shared-${domain.id}`}
            value={pw}
            onChange={setPw}
            error={error ?? undefined}
          />
          {domain.password_set && sharedCount > 0 && (
            <p className="hint">
              Changes it at Purelymail for the {sharedCount} account(s) that use
              it.
            </p>
          )}
          <div className="actions">
            <button type="submit" disabled={busy || pw.length < 12}>
              {busy ? 'Saving…' : 'Save'}
            </button>
            {domain.password_set && (
              <button
                type="button"
                className="secondary"
                onClick={() => {
                  setEditing(false)
                  setPw('')
                  setError(null)
                }}
              >
                Cancel
              </button>
            )}
          </div>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
        </form>
      )}
    </div>
  )
}

function AccountRow({
  account: a,
  canEdit,
  canChange,
  busy,
  sharedSet,
  onRemove,
  onUseShared,
  onOwnSaved,
}: {
  account: MailAccount
  canEdit: boolean
  canChange: boolean
  busy: string | null
  sharedSet: boolean
  onRemove: () => void
  onUseShared: () => void
  onOwnSaved: (v: MailAccounts) => void
}) {
  const [editing, setEditing] = useState(false)
  const [pw, setPw] = useState('')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function save(e: FormEvent) {
    e.preventDefault()
    setSaving(true)
    setError(null)
    try {
      onOwnSaved(await api.setMailAccountPassword(a.id, { password: pw }))
      setEditing(false)
    } catch (err) {
      setError(
        err instanceof ApiError && err.fields.password
          ? err.fields.password
          : message(err),
      )
    } finally {
      setSaving(false)
    }
  }

  return (
    <tr>
      <td className="mono">{a.address}</td>
      <td>
        <span className={`badge ${a.own_password ? '' : 'cert-valid'}`}>
          {a.own_password ? 'Own' : 'Shared'}
        </span>{' '}
        <SecretValue
          canSee={canEdit}
          load={() =>
            api.revealMailAccountPassword(a.id).then((r) => r.password)
          }
        />
        {editing && (
          <form className="pw-form" onSubmit={(e) => void save(e)}>
            <label htmlFor={`own-${a.id}`}>Own password</label>
            <PasswordInput id={`own-${a.id}`} value={pw} onChange={setPw} />
            <div className="actions">
              <button
                type="submit"
                className="small"
                disabled={saving || pw.length < 12}
              >
                {saving ? 'Saving…' : 'Save'}
              </button>
              <button
                type="button"
                className="secondary small"
                onClick={() => setEditing(false)}
              >
                Cancel
              </button>
            </div>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
          </form>
        )}
      </td>
      <td>
        {a.on_purelymail === undefined ? (
          <span className="hint">—</span>
        ) : a.on_purelymail ? (
          <span className="badge cert-valid">Yes</span>
        ) : (
          <span className="badge cert-expired" title="Deleted at Purelymail?">
            Missing
          </span>
        )}
      </td>
      {canEdit && (
        <td>
          <div className="row-actions">
            {canChange && !editing && (
              <button className="link" onClick={() => setEditing(true)}>
                {a.own_password ? 'Change password' : 'Own password'}
              </button>
            )}
            {canChange && a.own_password && sharedSet && (
              <button
                className="link"
                disabled={busy === `pw-${a.id}`}
                onClick={onUseShared}
              >
                Use shared
              </button>
            )}
            {canChange && (
              <button
                className="link danger"
                disabled={busy === `del-${a.id}`}
                onClick={onRemove}
              >
                {busy === `del-${a.id}` ? 'Deleting…' : 'Delete'}
              </button>
            )}
          </div>
        </td>
      )}
    </tr>
  )
}

function AddAccounts({
  domain,
  missing,
  busy,
  onAdd,
}: {
  domain: MailDomain
  missing: string[]
  busy: boolean
  onAdd: (names: string[], password?: string) => Promise<boolean>
}) {
  const [name, setName] = useState('')
  const [own, setOwn] = useState(false)
  const [pw, setPw] = useState('')
  const ready = domain.password_set

  async function submit(e: FormEvent) {
    e.preventDefault()
    if (await onAdd([name], own ? pw : undefined)) {
      setName('')
      setPw('')
      setOwn(false)
    }
  }

  const list = (ns: string[]) =>
    ns.length <= 1
      ? ns.join('')
      : `${ns.slice(0, -1).join(', ')} and ${ns[ns.length - 1]}`

  return (
    <div className="add-accounts">
      <h3>Add accounts</h3>
      {!ready && (
        <p className="hint">
          Set the shared password first, or give the account its own below.
        </p>
      )}
      {missing.length > 0 && (
        <div className="actions">
          <button disabled={busy || !ready} onClick={() => void onAdd(missing)}>
            {busy ? 'Adding…' : `Add ${list(missing)}`}
          </button>
          <span className="hint">Each gets the shared password.</span>
        </div>
      )}
      <form className="add-account" onSubmit={(e) => void submit(e)}>
        <label htmlFor={`acct-${domain.id}`}>Another address</label>
        <div className="address-input">
          <input
            id={`acct-${domain.id}`}
            className="mono"
            value={name}
            placeholder="billing"
            autoComplete="off"
            spellCheck={false}
            onChange={(e) => setName(e.target.value)}
          />
          <span className="mono">@{domain.domain}</span>
        </div>
        <label className="inline">
          <input
            type="checkbox"
            checked={own}
            onChange={(e) => setOwn(e.target.checked)}
          />
          Its own password instead of the shared one
        </label>
        {own && (
          <PasswordInput
            id={`acct-pw-${domain.id}`}
            value={pw}
            onChange={setPw}
          />
        )}
        <div className="actions">
          <button
            type="submit"
            className="secondary"
            disabled={busy || !name.trim() || (own ? pw.length < 12 : !ready)}
          >
            Add account
          </button>
        </div>
      </form>
    </div>
  )
}
