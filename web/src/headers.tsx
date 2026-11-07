import type { HeaderRule } from './api'

/** Edits a list of header rules: set / add / delete a header. */
export function HeaderEditor({
  label,
  hint,
  rules,
  onChange,
  error,
}: {
  label: string
  hint: string
  rules: HeaderRule[]
  onChange: (rules: HeaderRule[]) => void
  error?: string
}) {
  const update = (i: number, patch: Partial<HeaderRule>) =>
    onChange(rules.map((r, j) => (i === j ? { ...r, ...patch } : r)))
  return (
    <div className="header-editor">
      <span className="label">{label}</span>
      <span className="hint">{hint}</span>
      {rules.map((r, i) => (
        <div className="header-row" key={i}>
          <select
            aria-label="Operation"
            value={r.op}
            onChange={(e) =>
              update(i, { op: e.target.value as HeaderRule['op'] })
            }
          >
            <option value="set">Set</option>
            <option value="add">Add</option>
            <option value="delete">Delete</option>
          </select>
          <input
            aria-label="Header name"
            className="mono"
            placeholder="X-Header-Name"
            value={r.name}
            onChange={(e) => update(i, { name: e.target.value })}
          />
          <input
            aria-label="Value"
            className="mono"
            placeholder={r.op === 'delete' ? '' : 'value'}
            disabled={r.op === 'delete'}
            value={r.op === 'delete' ? '' : r.value}
            onChange={(e) => update(i, { value: e.target.value })}
          />
          <button
            type="button"
            className="link danger"
            onClick={() => onChange(rules.filter((_, j) => j !== i))}
          >
            Remove
          </button>
        </div>
      ))}
      {error && <span className="field-error">{error}</span>}
      <div>
        <button
          type="button"
          className="secondary"
          onClick={() =>
            onChange([...rules, { op: 'set', name: '', value: '' }])
          }
        >
          Add header rule
        </button>
      </div>
    </div>
  )
}
