import { useEffect, useState, type FormEvent } from 'react'
import { api, ApiError, message, type MailSettings } from './api'
import { PageHeader } from './shell'

/**
 * External connections: the sign-ins and API keys Switchyard uses to talk
 * to other services. Admins only.
 */
export function ConnectionsPage() {
  return (
    <div className="page">
      <PageHeader
        title="External connections"
        subtitle="Accounts and API keys Switchyard uses to work with other services. Keys are stored encrypted and never shown again."
      />
      <PurelymailCard />
    </div>
  )
}

function PurelymailCard() {
  const [settings, setSettings] = useState<MailSettings | null>(null)
  const [editing, setEditing] = useState<'key' | 'ownership' | null>(null)
  const [draft, setDraft] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    api
      .mailSettings()
      .then(setSettings)
      .catch((err: unknown) => setError(message(err)))
  }, [])

  async function save(body: Parameters<typeof api.saveMailSettings>[0]) {
    setError(null)
    setBusy(true)
    try {
      setSettings(await api.saveMailSettings(body))
      setEditing(null)
      setDraft('')
    } catch (err) {
      setError(
        err instanceof ApiError && (err.fields.api_key || err.fields.ownership)
          ? (err.fields.api_key ?? err.fields.ownership)
          : message(err),
      )
    } finally {
      setBusy(false)
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault()
    void save(editing === 'key' ? { api_key: draft } : { ownership: draft })
  }

  function edit(what: 'key' | 'ownership') {
    setError(null)
    setDraft(what === 'ownership' ? (settings?.ownership ?? '') : '')
    setEditing(what)
  }

  const ownership = settings?.ownership ?? ''
  const keySet = settings?.key_set ?? false
  return (
    <section className="card">
      <h2>Purelymail</h2>
      <p className="hint">
        Used by <a href="#/mail">Mail domains</a>. With an API key, Switchyard
        fetches your ownership proof, adds domains to Purelymail once their
        records are in, shows what Purelymail sees, and creates and changes
        email accounts. Create the key in Purelymail’s account settings (API
        access). Without one, paste the ownership proof by hand: Purelymail
        shows it on its <strong>Add new domain</strong> page.
      </p>
      {settings && (
        <div className="pm-settings">
          <span className="pm-label">API key</span>
          <div className="actions">
            {keySet ? (
              <span className="badge cert-valid">Saved</span>
            ) : (
              <span className="badge cert-not_needed">Not set</span>
            )}
            {editing !== 'key' && (
              <>
                <button className="secondary small" onClick={() => edit('key')}>
                  {keySet ? 'Replace' : 'Add API key'}
                </button>
                {keySet && (
                  <button
                    className="link danger"
                    disabled={busy}
                    onClick={() => {
                      if (
                        confirm(
                          'Remove the Purelymail API key? The ownership proof stays, but email accounts can’t be created or changed until a key is added again.',
                        )
                      )
                        void save({ clear_key: true })
                    }}
                  >
                    Remove
                  </button>
                )}
              </>
            )}
          </div>
          <span className="pm-label">Ownership proof</span>
          <div className="actions">
            {ownership ? (
              <span className="mono pm-proof">{ownership}</span>
            ) : (
              <span className="badge cert-pending">Not set</span>
            )}
            {keySet && ownership && (
              <span className="hint">from Purelymail</span>
            )}
            {!keySet && editing !== 'ownership' && (
              <button
                className="secondary small"
                onClick={() => edit('ownership')}
              >
                {ownership ? 'Change' : 'Set by hand'}
              </button>
            )}
          </div>
        </div>
      )}
      {editing && (
        <form className="actions wildcard-form" onSubmit={submit}>
          <label className="grow">
            {editing === 'key' ? 'Purelymail API key' : 'Ownership TXT value'}
            <input
              className="mono"
              type={editing === 'key' ? 'password' : 'text'}
              autoFocus
              required={editing === 'key'}
              autoComplete="off"
              placeholder={
                editing === 'key' ? '' : 'purelymail_ownership_proof=…'
              }
              value={draft}
              onChange={(e) => setDraft(e.target.value)}
            />
          </label>
          <button disabled={busy}>
            {busy && editing === 'key' ? 'Checking with Purelymail…' : 'Save'}
          </button>
          <button
            type="button"
            className="secondary"
            onClick={() => setEditing(null)}
          >
            Cancel
          </button>
        </form>
      )}
      {editing === 'key' && (
        <p className="hint">
          Switchyard checks the key with Purelymail before saving it, and keeps
          it encrypted. It’s never shown again.
        </p>
      )}
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
    </section>
  )
}
