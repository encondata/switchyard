// Types for the HSL Suite kit (src/hsl-ui/suite.js): its two custom elements and window.HSLSuite.
import type { DetailedHTMLProps, HTMLAttributes } from 'react'

type HslElement = DetailedHTMLProps<HTMLAttributes<HTMLElement>, HTMLElement>

declare module 'react' {
  namespace JSX {
    interface IntrinsicElements {
      'hsl-app-switcher': HslElement & {
        apps?: string
        current?: string
        label?: string
      }
      'hsl-user-menu': HslElement & {
        name?: string
        detail?: string
        'profile-url'?: string
        'profile-label'?: string
        'signout-label'?: string
      }
    }
  }
}

declare global {
  interface Window {
    HSLSuite: {
      version: string
      theme: {
        key: string
        get: () => 'light' | 'dark'
        set: (theme: 'light' | 'dark') => 'light' | 'dark'
        toggle: () => 'light' | 'dark'
        migrate: (oldKeys: string[]) => 'light' | 'dark'
      }
      mark: (size?: number) => SVGSVGElement
    }
  }
}
