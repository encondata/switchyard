import { Mark } from './shell'
import { ssoStart } from './sso'

// The HackSpaceLabs sign-in button and signed-out page (logic in sso.ts), in the kit's sign-in card.

export function SsoButton({ prompt }: { prompt?: 'login' }) {
  return (
    <a className="hsl-auth-button is-sso" href={ssoStart({ prompt })}>
      <Mark size={20} />
      Sign in with HackSpaceLabs
    </a>
  )
}

export function SignedOut() {
  return (
    <>
      <h1 className="hsl-auth-title">You’re signed out of HackSpaceLabs</h1>
      <p className="hsl-auth-text">
        You’re signed out of Switchyard and the other HackSpaceLabs apps.
      </p>
      <SsoButton />
    </>
  )
}
