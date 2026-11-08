import { useEffect, useRef } from 'react'
import {
  CloudOff,
  GitCompareArrows,
  ShieldAlert,
  TriangleAlert,
  type LucideIcon,
} from 'lucide-react'
import type { Alert } from './api'

/* ---------- Toasts ---------- */

export type Tone = 'info' | 'good' | 'bad'
type Toast = {
  id: number
  tone: Tone
  title: string
  body?: string
  href?: string
}

let toasts: Toast[] = []
let nextId = 1
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

/** Show a short message in the corner. It goes away by itself after a few seconds. */
export function toast(
  title: string,
  opts: { tone?: Tone; body?: string; href?: string } = {},
) {
  const t: Toast = {
    id: nextId++,
    tone: opts.tone ?? 'info',
    title,
    body: opts.body,
    href: opts.href,
  }
  toasts = [...toasts, t].slice(-4)
  emit()
  setTimeout(() => dismiss(t.id), t.tone === 'bad' ? 10_000 : 6_000)
}

export function dismiss(id: number) {
  toasts = toasts.filter((t) => t.id !== id)
  emit()
}

export function subscribe(l: () => void) {
  listeners.add(l)
  return () => {
    listeners.delete(l)
  }
}

export const snapshot = () => toasts

/* ---------- Alert notifications ---------- */

const kindInfo: Record<
  string,
  { title: string; icon: LucideIcon; href: string }
> = {
  caddy_unreachable: {
    title: 'Caddy unreachable',
    icon: CloudOff,
    href: '#/health',
  },
  drift: { title: 'Config drift', icon: GitCompareArrows, href: '#/changes' },
  apply_failed: {
    title: 'Apply failed',
    icon: TriangleAlert,
    href: '#/history',
  },
  cert_expiring: {
    title: 'Certificate expiring',
    icon: ShieldAlert,
    href: '#/certificates',
  },
  cert_failed: {
    title: 'Certificate failed',
    icon: ShieldAlert,
    href: '#/certificates',
  },
}

export function info(kind: string) {
  return (
    kindInfo[kind] ?? { title: 'Alert', icon: TriangleAlert, href: '#/health' }
  )
}

/** One notification per alert: raised, or cleared once it resolves. */
type Note = { key: string; alert: Alert; resolved: boolean; at: string }

export function notesFrom(alerts: Alert[]): Note[] {
  const out: Note[] = []
  for (const a of alerts) {
    out.push({
      key: `${a.id}:open`,
      alert: a,
      resolved: false,
      at: a.created_at,
    })
    if (a.resolved_at)
      out.push({
        key: `${a.id}:resolved`,
        alert: a,
        resolved: true,
        at: a.resolved_at,
      })
  }
  return out.sort((x, y) => y.at.localeCompare(x.at)).slice(0, 30)
}

export function ago(iso: string): string {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return 'just now'
  if (s < 3600) return `${Math.floor(s / 60)} min ago`
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`
  return new Date(iso).toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
  })
}

/**
 * Toasts each alert event that arrives after the page loaded. Existing
 * alerts at sign-in are not toasted; they're in the bell and the banner.
 */
export function useAlertToasts(alerts: Alert[] | null) {
  const seen = useRef<Set<string> | null>(null)
  useEffect(() => {
    if (!alerts) return
    const notes = notesFrom(alerts)
    if (seen.current) {
      for (const n of notes
        .filter((n) => !seen.current!.has(n.key))
        .reverse()) {
        const i = info(n.alert.kind)
        toast(n.resolved ? `Resolved: ${i.title}` : i.title, {
          tone: n.resolved ? 'good' : 'bad',
          body: noteText(n),
          href: i.href,
        })
      }
    }
    seen.current = new Set(notes.map((n) => n.key))
  }, [alerts])
}

/** The line under a notification's title: the alert, or what recovered. */
export function noteText(n: Note): string {
  if (!n.resolved) return n.alert.message
  return n.alert.kind.startsWith('cert_')
    ? `${n.alert.subject}: certificate is fine again.`
    : 'Back to normal.'
}
