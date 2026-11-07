import { useCallback, useEffect, useState } from 'react'
import { api, ApiError, type Alert, type Preview, type User } from './api'
import { ChangePassword, Login } from './auth'
import { Changes, History } from './config'
import { AccessPage } from './access'
import { DNSPage } from './dns'
import { Certificates, HealthPage } from './ops'
import { HostEditor, HostList } from './hosts'
import { AccountPage, EnrollRequired } from './account'
import { AuditPage, UsersPage } from './users'
import { ImportPage } from './importer'
import { Dashboard } from './dashboard'
import { HoneypotPage } from './honeypot'

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

  const ready = !!user && !user.must_change_password && !user.must_enroll_2fa
  const refreshPending = useCallback(() => {
    api
      .preview()
      .then(setPreview)
      .catch(() => setPreview(null))
  }, [])
  useEffect(() => {
    if (ready) refreshPending()
  }, [ready, route, refreshPending])

  // Open alerts show on every page (spec F2).
  const [alerts, setAlerts] = useState<Alert[]>([])
  useEffect(() => {
    if (!ready) return
    const load = () =>
      api
        .alerts()
        .then(setAlerts)
        .catch(() => setAlerts([]))
    load()
    const t = setInterval(load, 60_000)
    return () => clearInterval(t)
  }, [ready, route])

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
  else if (user.must_enroll_2fa)
    body = (
      <EnrollRequired
        onDone={() => {
          void api.me().then(setUser)
        }}
      />
    )
  else if (route === '/account')
    body = (
      <AccountPage
        user={user}
        onChangePassword={() => setChangingPassword(true)}
        onChanged={() => void api.me().then(setUser)}
      />
    )
  else if (route === '/users' && user.role === 'admin')
    body = <UsersPage me={user} />
  else if (route === '/audit' && user.role === 'admin') body = <AuditPage />
  else if (route === '/import' && user.role === 'admin')
    body = <ImportPage onImported={refreshPending} />
  else if (route.startsWith('/hosts/new')) {
    const q = new URLSearchParams(route.split('?')[1] ?? '')
    const folder = q.get('folder')
    const clone = q.get('clone')
    body = (
      <HostEditor
        key={route}
        id={null}
        folderId={folder ? Number(folder) : null}
        cloneId={clone ? Number(clone) : null}
        isAdmin={user.role === 'admin'}
        onSaved={() => (location.hash = '#/hosts')}
      />
    )
  } else if (route.startsWith('/hosts/'))
    body = (
      <HostEditor
        key={route}
        id={Number(route.split('/')[2])}
        isAdmin={user.role === 'admin'}
        onSaved={() => (location.hash = '#/hosts')}
      />
    )
  else if (route === '/changes')
    body = <Changes canEdit={canEdit} onApplied={refreshPending} />
  else if (route === '/history')
    body = <History canEdit={canEdit} onRolledBack={refreshPending} />
  else if (route === '/status' || route === '/health')
    body = <HealthPage isAdmin={user.role === 'admin'} />
  else if (route === '/dashboard') body = <Dashboard canEdit={canEdit} />
  else if (route === '/honeypot')
    body = (
      <HoneypotPage
        canEdit={canEdit}
        isAdmin={user.role === 'admin'}
        onChanged={refreshPending}
      />
    )
  else if (route === '/certificates') body = <Certificates canEdit={canEdit} />
  else if (route === '/dns')
    body = (
      <DNSPage isAdmin={user.role === 'admin'} onChanged={refreshPending} />
    )
  else if (route === '/access')
    body = <AccessPage canEdit={canEdit} onChanged={refreshPending} />
  else
    body = (
      <HostList
        canEdit={canEdit}
        isAdmin={user.role === 'admin'}
        onChanged={refreshPending}
      />
    )

  const nav = [
    ['/dashboard', 'Dashboard'],
    ['/hosts', 'Hosts'],
    ['/access', 'Access'],
    ['/dns', 'DNS'],
    ['/honeypot', 'Honeypot'],
    ['/certificates', 'Certificates'],
    ['/changes', 'Review & apply'],
    ['/history', 'History'],
    ['/health', 'Health'],
    ...(user?.role === 'admin'
      ? [
          ['/users', 'Users'],
          ['/audit', 'Audit'],
        ]
      : []),
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
            {ready ? (
              <a href="#/account" title="Your account and two-factor sign-in">
                {user.username}
              </a>
            ) : (
              <span>{user.username}</span>
            )}
            <button className="link" onClick={signOut}>
              Sign out
            </button>
          </nav>
        )}
      </header>
      {ready && alerts.length > 0 && route !== '/health' && (
        <div className="banner alert">
          {alerts.length === 1
            ? alerts[0].message
            : `${alerts.length} alerts need attention.`}{' '}
          <a href="#/health">See health</a>
        </div>
      )}
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
