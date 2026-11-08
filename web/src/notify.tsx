import {
  useCallback,
  useEffect,
  useRef,
  useState,
  useSyncExternalStore,
} from 'react'
import { Bell, CircleCheck, TriangleAlert, X } from 'lucide-react'
import type { Alert } from './api'
import {
  ago,
  dismiss,
  info,
  notesFrom,
  noteText,
  snapshot,
  subscribe,
} from './toast'

export function Toaster() {
  const list = useSyncExternalStore(subscribe, snapshot)
  return (
    <div className="toaster" aria-live="polite">
      {list.map((t) => {
        const Icon =
          t.tone === 'bad'
            ? TriangleAlert
            : t.tone === 'good'
              ? CircleCheck
              : Bell
        return (
          <div
            key={t.id}
            className={`toast toast-${t.tone}`}
            role={t.tone === 'bad' ? 'alert' : 'status'}
          >
            <Icon size={18} aria-hidden="true" />
            <div className="toast-text">
              <strong>{t.title}</strong>
              {t.body && <span>{t.body}</span>}
              {t.href && (
                <a href={t.href} onClick={() => dismiss(t.id)}>
                  View
                </a>
              )}
            </div>
            <button
              className="icon-btn"
              aria-label="Dismiss"
              onClick={() => dismiss(t.id)}
            >
              <X size={16} aria-hidden="true" />
            </button>
          </div>
        )
      })}
    </div>
  )
}

const readKey = (user: string) => `cpm-notes-read:${user}`

/** The bell in the top bar: unread count and a dropdown of recent alert events. */
export function NotificationBell({
  alerts,
  username,
}: {
  alerts: Alert[] | null
  username: string
}) {
  const [open, setOpen] = useState(false)
  const [readAt, setReadAt] = useState(() => {
    try {
      return localStorage.getItem(readKey(username)) ?? ''
    } catch {
      return ''
    }
  })
  const box = useRef<HTMLDivElement>(null)
  const notes = notesFrom(alerts ?? [])
  const unread = notes.filter((n) => n.at > readAt).length

  const markRead = useCallback(() => {
    const now = new Date().toISOString()
    setReadAt(now)
    try {
      localStorage.setItem(readKey(username), now)
    } catch {
      // read state lasts for this visit only
    }
  }, [username])

  // Closing the menu counts as having seen everything in it.
  const close = useCallback(() => {
    setOpen(false)
    markRead()
  }, [markRead])

  useEffect(() => {
    if (!open) return
    const onDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) close()
    }
    const onKey = (e: KeyboardEvent) => e.key === 'Escape' && close()
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => {
      document.removeEventListener('mousedown', onDown)
      document.removeEventListener('keydown', onKey)
    }
  }, [open, close])

  return (
    <div className="bell" ref={box}>
      <button
        className="icon-btn bell-btn"
        aria-label={
          unread ? `Notifications, ${unread} unread` : 'Notifications'
        }
        aria-expanded={open}
        onClick={() => (open ? close() : setOpen(true))}
      >
        <Bell size={19} strokeWidth={1.8} aria-hidden="true" />
        {unread > 0 && (
          <span className="bell-count">{unread > 9 ? '9+' : unread}</span>
        )}
      </button>
      {open && (
        <div className="bell-menu" role="dialog" aria-label="Notifications">
          <div className="bell-head">
            <strong>Notifications</strong>
            {unread > 0 && (
              <button className="link" onClick={markRead}>
                Mark all as read
              </button>
            )}
          </div>
          {notes.length === 0 ? (
            <p className="bell-empty">
              <CircleCheck size={20} aria-hidden="true" />
              No alerts. CPM will tell you here when Caddy, a certificate or an
              apply needs attention.
            </p>
          ) : (
            <ul className="bell-list">
              {notes.map((n) => {
                const i = info(n.alert.kind)
                const Icon = n.resolved ? CircleCheck : i.icon
                return (
                  <li key={n.key} className={n.at > readAt ? 'unread' : ''}>
                    <a
                      href={i.href}
                      onClick={close}
                      className={
                        n.resolved
                          ? 'note-good'
                          : n.alert.resolved_at
                            ? 'note-past'
                            : 'note-bad'
                      }
                    >
                      <Icon size={18} aria-hidden="true" />
                      <span className="note-text">
                        <strong>
                          {n.resolved ? `Resolved: ${i.title}` : i.title}
                        </strong>
                        <span>{noteText(n)}</span>
                        <span className="hint">{ago(n.at)}</span>
                      </span>
                    </a>
                  </li>
                )
              })}
            </ul>
          )}
          <a className="bell-foot" href="#/health" onClick={close}>
            Open health
          </a>
        </div>
      )}
    </div>
  )
}
