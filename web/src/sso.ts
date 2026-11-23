import type { AuthConfig } from './api'

// Sign in with HackSpaceLabs (PLAN.md 5.9 in encondata/hsl-suite).

/** What each ?error= from the HackSpaceLabs sign-in means. */
const ssoErrors: Record<string, string> = {
  sso_expired: 'That sign-in took too long or was already used. Try again.',
  sso_cancelled: 'Sign-in was cancelled.',
  sso_failed:
    'Signing in with HackSpaceLabs didn’t work. Try again, or ask an administrator.',
  sso_unavailable:
    'HackSpaceLabs sign-in can’t be reached right now. Administrators can use a local account below.',
  no_access:
    'Your HackSpaceLabs account doesn’t have access to Switchyard. Ask an administrator.',
  account_exists:
    'A Switchyard account with your HackSpaceLabs username already exists. Ask an administrator to rename or remove it.',
  username_invalid:
    'Your HackSpaceLabs username can’t be used in Switchyard (2–64 letters, digits, dots, dashes, underscores or @). Ask an administrator.',
}

export function ssoError(code: string | null): string | null {
  if (!code) return null
  return ssoErrors[code] ?? 'Sign-in didn’t work. Try again.'
}

/** Where to come back to after signing in: this page, including its #/route. */
export function returnPath(): string {
  return '/' + location.hash
}

export function ssoStart(opts: { prompt?: 'login' } = {}): string {
  const q = new URLSearchParams({ next: returnPath() })
  if (opts.prompt) q.set('prompt', opts.prompt)
  return '/api/auth/oidc/login?' + q.toString()
}

const tryKey = 'cpm-sso-try'

/**
 * Sends a signed-out visitor to HackSpaceLabs when auto-redirect is on. Returns true if it did. It
 * won't go twice within 30 seconds: if a sign-in "succeeds" but no session sticks (say, a Secure cookie
 * on plain HTTP), the app would otherwise bounce between here and Keycloak forever.
 */
export function maybeAutoRedirect(config: AuthConfig | null): boolean {
  if (!config?.oidc.enabled || !config.oidc.auto_redirect) return false
  const q = new URLSearchParams(location.search)
  if (location.pathname === '/signed-out' || q.has('local') || q.has('error'))
    return false
  let last = 0
  try {
    last = Number(sessionStorage.getItem(tryKey) ?? 0)
  } catch {
    /* storage blocked: no guard, still fine */
  }
  if (Date.now() - last < 30_000) {
    history.replaceState(null, '', '/login?error=sso_failed' + location.hash)
    return false
  }
  try {
    sessionStorage.setItem(tryKey, String(Date.now()))
  } catch {
    /* ignore */
  }
  location.assign(ssoStart())
  return true
}

/** Called once a page has loaded signed in. */
export function clearAutoRedirectGuard() {
  try {
    sessionStorage.removeItem(tryKey)
  } catch {
    /* ignore */
  }
  // Tidy /login?… or /signed-out out of the address bar, keeping the #/route.
  if (location.pathname !== '/' || location.search)
    history.replaceState(null, '', '/' + location.hash)
}
