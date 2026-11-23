import { Mark } from './shell'
import { ssoStart } from './sso'

// The HackSpaceLabs sign-in button and signed-out page (logic in sso.ts).

export function SsoButton({ prompt }: { prompt?: 'login' }) {
  return (
    <a className="button sso-button" href={ssoStart({ prompt })}>
      <Mark size={20} />
      Sign in with HackSpaceLabs
    </a>
  )
}

export function SignedOut() {
  return (
    <div className="card narrow">
      <h1>You’re signed out of HackSpaceLabs</h1>
      <p className="hint">
        You’re signed out of Switchyard and the other HackSpaceLabs apps.
      </p>
      <SsoButton />
    </div>
  )
}
