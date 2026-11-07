import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Preview, type User } from './api'
import { ChangePassword, Login } from './auth'
import { Changes, History, StatusPage } from './config'
import { AccessPage } from './access'
import { HostEditor, HostList } from './hosts'

// Hash routes: #/hosts, #/hosts/new, #/hosts/3, #/changes, #/history, #/status
function useRoute(): string {
  const [route, setRoute] = useState(location.hash.slice(1) || '/hosts')
  useEffect(() => {
    const on = () => setRoute(location.hash.slice(1) || '/hosts')
    window.addEventListener('hashchange', on)
    return () => window.removeEventListener('hashchange', on)
  }, [])
  return route
}

function App() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)
  const [changingPassword, setChangingPassword] = useState(false)
  const [preview, setPreview] = useState<Preview | null>(null)
  const route = useRoute()

  useEffect(() => {
    api
      .me()
      .then(setUser)
      .catch((err: unknown) => {
        if (!(err instanceof ApiError && err.status === 401)) console.error(err)
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    const out = () => setUser(null)
    window.addEventListener('cpm:signed-out', out)
    return () => window.removeEventListener('cpm:signed-out', out)
  }, [])

  const ready = !!user && !user.must_change_password
  const refreshPending = useCallback(() => {
    api
      .preview()
      .then(setPreview)
      .catch(() => setPreview(null))
  }, [])
  useEffect(() => {
    if (ready) refreshPending()
  }, [ready, route, refreshPending])

  async function signOut() {
    await api.logout().catch(() => undefined)
    setUser(null)
    setChangingPassword(false)
  }

  const canEdit = user?.role === 'admin' || user?.role === 'editor'

  let body
  if (loading) body = <p>Loading…</p>
  else if (!user) body = <Login onSignedIn={setUser} />
  else if (user.must_change_password || changingPassword)
    body = (
      <ChangePassword
        user={user}
        onChanged={(u) => {
          setUser(u)
          setChangingPassword(false)
        }}
        onCancel={
          user.must_change_password
            ? undefined
            : () => setChangingPassword(false)
        }
      />
    )
  else if (route.startsWith('/hosts/new')) {
    const folder = new URLSearchParams(route.split('?')[1] ?? '').get('folder')
    body = (
      <HostEditor
        key={route}
        id={null}
        folderId={folder ? Number(folder) : null}
        onSaved={() => (location.hash = '#/hosts')}
      />
    )
  } else if (route.startsWith('/hosts/'))
    body = (
      <HostEditor
        key={route}
        id={Number(route.split('/')[2])}
        onSaved={() => (location.hash = '#/hosts')}
      />
    )
  else if (route === '/changes')
    body = <Changes canEdit={canEdit} onApplied={refreshPending} />
  else if (route === '/history')
    body = <History canEdit={canEdit} onRolledBack={refreshPending} />
  else if (route === '/status') body = <StatusPage />
  else if (route === '/access')
    body = <AccessPage canEdit={canEdit} onChanged={refreshPending} />
  else body = <HostList canEdit={canEdit} onChanged={refreshPending} />

  const nav = [
    ['/hosts', 'Hosts'],
    ['/access', 'Access'],
    ['/changes', 'Review & apply'],
    ['/history', 'History'],
    ['/status', 'Status'],
  ]

  return (
    <>
      <header>
        <strong>CaddyProxyManager</strong>
        {ready && (
          <nav className="main-nav">
            {nav.map(([path, label]) => (
              <a
                key={path}
                href={`#${path}`}
                className={route.startsWith(path) ? 'active' : ''}
              >
                {label}
                {path === '/changes' && preview?.pending && (
                  <span className="dot" aria-label="pending changes" />
                )}
              </a>
            ))}
          </nav>
        )}
        {user && (
          <nav>
            <span>{user.username}</span>
            {!user.must_change_password && (
              <button
                className="link"
                onClick={() => setChangingPassword(true)}
              >
                Change password
              </button>
            )}
            <button className="link" onClick={signOut}>
              Sign out
            </button>
          </nav>
        )}
      </header>
      {ready && preview?.pending && route !== '/changes' && (
        <div className="banner">
          {preview.drift
            ? 'Caddy’s running config differs from what CPM last applied.'
            : 'You have changes that aren’t applied to Caddy yet.'}{' '}
          <a href="#/changes">Review and apply</a>
        </div>
      )}
      <main>{body}</main>
    </>
  )
}

export default App
