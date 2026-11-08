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
import { Logo, Sidebar, Topbar } from './shell'
import { ArrowRight, TriangleAlert } from 'lucide-react'
import { applyAccent } from './accent'
import { Toaster } from './notify'
import { toast, useAlertToasts } from './toast'

// Hash routes: #/dashboard, #/hosts, #/hosts/new, #/hosts/3, #/changes, …
function useRoute(): string {
  const [route, setRoute] = useState(location.hash.slice(1) || '/dashboard')
  useEffect(() => {
    const on = () => setRoute(location.hash.slice(1) || '/dashboard')
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

  // The signed-in user's accent color follows them across browsers.
  const userId = user?.id
  useEffect(() => {
    if (!ready) return
    api
      .preferences()
      .then((p) => applyAccent(p.accent))
      .catch(() => undefined)
  }, [ready, userId])
  const refreshPending = useCallback(() => {
    api
      .preview()
      .then(setPreview)
      .catch(() => setPreview(null))
  }, [])
  useEffect(() => {
    if (ready) refreshPending()
  }, [ready, route, refreshPending])

  // Alerts feed the banner (open ones), the bell and toasts (spec F2).
  const [allAlerts, setAllAlerts] = useState<Alert[] | null>(null)
  useEffect(() => {
    if (!ready) {
      setAllAlerts(null) // eslint-disable-line react-hooks/set-state-in-effect
      return
    }
    const load = () =>
      api
        .alerts(true)
        .then(setAllAlerts)
        .catch(() => undefined)
    load()
    const t = setInterval(load, 30_000)
    return () => clearInterval(t)
  }, [ready, route])
  useAlertToasts(allAlerts)
  const alerts = (allAlerts ?? []).filter((a) => !a.resolved_at)

  async function signOut() {
    await api.logout().catch(() => undefined)
    applyAccent('')
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
    body = (
      <Changes
        canEdit={canEdit}
        onApplied={() => {
          refreshPending()
          toast('Changes applied', {
            tone: 'good',
            body: 'Caddy is running the new config.',
          })
        }}
      />
    )
  else if (route === '/history')
    body = <History canEdit={canEdit} onRolledBack={refreshPending} />
  else if (route === '/status' || route === '/health')
    body = <HealthPage isAdmin={user.role === 'admin'} />
  else if (route === '/hosts' || route.startsWith('/hosts?'))
    body = (
      <HostList
        canEdit={canEdit}
        isAdmin={user.role === 'admin'}
        onChanged={refreshPending}
      />
    )
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
      <Dashboard
        canEdit={canEdit}
        route={route}
        pending={preview?.pending ? preview.changes : 0}
      />
    )

  // Before sign-in, password change or 2FA enrollment: a centered page.
  if (!ready)
    return (
      <div className="bare">
        <div className="bare-logo">
          <Logo />
        </div>
        {body}
        {user && (
          <button className="link bare-out" onClick={signOut}>
            Sign out
          </button>
        )}
      </div>
    )

  const pending = preview?.pending ? preview.changes : 0
  return (
    <div className="shell">
      <Sidebar
        route={route}
        user={user}
        pending={pending}
        onSignOut={signOut}
      />
      <div className="main">
        <Topbar route={route} alerts={allAlerts} username={user.username} />
        <main className="content">
          {alerts.length > 0 && route !== '/health' && (
            <div className="banner banner-bad" role="alert">
              <TriangleAlert size={20} aria-hidden="true" />
              <span>
                {alerts.length === 1
                  ? alerts[0].message
                  : `${alerts.length} alerts need attention.`}
              </span>
              <a href="#/health">See health</a>
            </div>
          )}
          {pending > 0 && route !== '/changes' && (
            <div className="banner banner-warn" role="status">
              <TriangleAlert size={20} aria-hidden="true" />
              <span>
                {preview?.drift
                  ? 'Caddy is running a config CPM didn’t apply'
                  : `${pending} ${pending === 1 ? 'change' : 'changes'} ready to deploy`}
              </span>
              <a href="#/changes">
                Review & apply <ArrowRight size={16} aria-hidden="true" />
              </a>
            </div>
          )}
          {body}
        </main>
      </div>
      <Toaster />
    </div>
  )
}

export default App
