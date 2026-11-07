import { useEffect, useState } from 'react'
import { api, ApiError, message, type ConfigVersion, type Preview } from './api'

function Diff({ text }: { text: string }) {
  return (
    <pre className="diff">
      {text.split('\n').map((line, i) => {
        const cls =
          line.startsWith('+++') || line.startsWith('---')
            ? 'meta'
            : line.startsWith('+')
              ? 'add'
              : line.startsWith('-')
                ? 'del'
                : line.startsWith('@@')
                  ? 'meta'
                  : ''
        return (
          <span key={i} className={cls}>
            {line + '\n'}
          </span>
        )
      })}
    </pre>
  )
}

export function Changes({
  canEdit,
  onApplied,
}: {
  canEdit: boolean
  onApplied: () => void
}) {
  const [preview, setPreview] = useState<Preview | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [result, setResult] = useState<
    { ok: true; v: ConfigVersion } | { ok: false; msg: string } | null
  >(null)
  const [note, setNote] = useState('')
  const [busy, setBusy] = useState(false)

  function load() {
    api
      .preview()
      .then(setPreview)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  async function apply() {
    setBusy(true)
    setResult(null)
    try {
      const v = await api.apply(note)
      setResult({ ok: true, v })
      setNote('')
      onApplied()
    } catch (err) {
      setResult({
        ok: false,
        msg:
          err instanceof ApiError && err.code === 'caddy_rejected'
            ? `Caddy rejected the config and kept running the previous one: ${err.message}`
            : message(err),
      })
    } finally {
      setBusy(false)
      load()
    }
  }

  return (
    <section className="card">
      <h1>Review and apply</h1>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {result?.ok && (
        <p className="success" role="status">
          Applied as version {result.v.n}. Caddy is now running it.
        </p>
      )}
      {result && !result.ok && (
        <p className="error" role="alert">
          {result.msg}
        </p>
      )}
      {!preview && !error && <p>Comparing with Caddy…</p>}
      {preview?.caddy_error && (
        <p className="error">
          Can’t read Caddy’s config: {preview.caddy_error}
        </p>
      )}
      {preview?.drift && (
        <p className="notice">
          Caddy is running a config CPM didn’t apply last (it was changed
          outside CPM, or restarted without CPM’s config). Applying will put
          CPM’s config back.
        </p>
      )}
      {preview && !preview.pending && (
        <p>Caddy is running exactly what CPM has. Nothing to apply.</p>
      )}
      {preview?.pending && (
        <>
          <p>
            These are the changes to Caddy’s config. Red lines are removed,
            green lines added. If Caddy rejects the new config, it keeps running
            the current one.
          </p>
          <Diff text={preview.diff} />
          {canEdit && (
            <div className="actions">
              <input
                className="grow"
                placeholder="Note for the history (optional)"
                value={note}
                onChange={(e) => setNote(e.target.value)}
              />
              <button onClick={apply} disabled={busy}>
                {busy ? 'Applying…' : 'Apply to Caddy'}
              </button>
            </div>
          )}
        </>
      )}
    </section>
  )
}

export function History({
  canEdit,
  onRolledBack,
}: {
  canEdit: boolean
  onRolledBack: () => void
}) {
  const [versions, setVersions] = useState<ConfigVersion[] | null>(null)
  const [open, setOpen] = useState<ConfigVersion | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [info, setInfo] = useState<string | null>(null)

  function load() {
    api
      .versions()
      .then(setVersions)
      .catch((err: unknown) => setError(message(err)))
  }
  useEffect(load, [])

  const [mode, setMode] = useState<'diff' | 'json'>('diff')
  const [diff, setDiff] = useState<{ diff: string; previous: number } | null>(
    null,
  )

  async function view(n: number, m: 'diff' | 'json') {
    if (open?.n === n && mode === m) return setOpen(null)
    try {
      const [v, d] = await Promise.all([api.version(n), api.versionDiff(n)])
      setOpen(v)
      setDiff(d)
      setMode(m)
    } catch (err) {
      setError(message(err))
    }
  }

  async function rollback(n: number) {
    if (
      !confirm(
        `Send version ${n} to Caddy again? Your hosts in CPM stay as they are, so their changes will show as pending afterwards.`,
      )
    )
      return
    setError(null)
    try {
      const v = await api.rollback(n)
      setInfo(
        `Rolled back: Caddy is running version ${n} (recorded as ${v.n}).`,
      )
      load()
      onRolledBack()
    } catch (err) {
      setError(message(err))
    }
  }

  return (
    <section className="card">
      <h1>Config history</h1>
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
      {versions?.length === 0 && <p>Nothing has been applied yet.</p>}
      {versions && versions.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>#</th>
                <th>When</th>
                <th>Who</th>
                <th>Result</th>
                <th>Note</th>
                <th aria-label="Actions" />
              </tr>
            </thead>
            <tbody>
              {versions.map((v) => (
                <tr key={v.n}>
                  <td>{v.n}</td>
                  <td>{new Date(v.applied_at).toLocaleString()}</td>
                  <td>{v.applied_by}</td>
                  <td>
                    {v.result === 'ok' ? (
                      <span className="ok">Applied</span>
                    ) : (
                      <span className="bad" title={v.error}>
                        Rejected
                      </span>
                    )}
                    {v.error && <div className="hint">{v.error}</div>}
                  </td>
                  <td>{v.note}</td>
                  <td>
                    <div className="row-actions">
                      <button
                        className="link"
                        onClick={() => view(v.n, 'diff')}
                      >
                        Changes
                      </button>
                      <button
                        className="link"
                        onClick={() => view(v.n, 'json')}
                      >
                        Full config
                      </button>
                      {canEdit && v.result === 'ok' && (
                        <button className="link" onClick={() => rollback(v.n)}>
                          Roll back
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {open && (
        <>
          <div className="toolbar">
            <h2>
              Version {open.n}
              {mode === 'diff' &&
                (diff?.previous
                  ? ` — changes since version ${diff.previous}`
                  : ' — the first applied config')}
            </h2>
            <button className="link" onClick={() => setOpen(null)}>
              Close
            </button>
          </div>
          {mode === 'diff' && diff ? (
            diff.diff ? (
              <Diff text={diff.diff} />
            ) : (
              <p className="hint">Same config as the version before.</p>
            )
          ) : (
            <pre className="diff">{open.json}</pre>
          )}
        </>
      )}
    </section>
  )
}
