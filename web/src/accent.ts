/** Accent colors offered in Account > Preferences. All keep white button text readable. */
export const accentPresets: { name: string; hex: string }[] = [
  { name: 'Switchyard', hex: '' },
  { name: 'Green', hex: '#0e7c61' },
  { name: 'Blue', hex: '#2563eb' },
  { name: 'Indigo', hex: '#4f46e5' },
  { name: 'Purple', hex: '#7c3aed' },
  { name: 'Pink', hex: '#be185d' },
  { name: 'Red', hex: '#c62828' },
  { name: 'Orange', hex: '#c2410c' },
  { name: 'Slate', hex: '#475569' },
]

export const defaultAccent = '#038076'

const storageKey = 'cpm-accent'

/** Use this accent everywhere ('' = default) and remember it for the next page load. */
export function applyAccent(hex: string) {
  const root = document.documentElement
  if (hex) root.style.setProperty('--accent-base', hex)
  else root.style.removeProperty('--accent-base')
  try {
    if (hex) localStorage.setItem(storageKey, hex)
    else localStorage.removeItem(storageKey)
  } catch {
    // not remembered; the server copy loads after sign-in
  }
}

/** Apply the last-used accent before first paint, so it doesn't flash the default. */
export function applyStoredAccent() {
  try {
    const hex = localStorage.getItem(storageKey)
    if (hex && /^#[0-9a-f]{6}$/.test(hex))
      document.documentElement.style.setProperty('--accent-base', hex)
  } catch {
    // storage unavailable: default accent until prefs load
  }
}

/** WCAG contrast of #rrggbb against white (the server enforces >= 4.5 too). */
export function contrastWithWhite(hex: string): number {
  const lin = (i: number) => {
    const c = parseInt(hex.slice(i, i + 2), 16) / 255
    return c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
  }
  const l = 0.2126 * lin(1) + 0.7152 * lin(3) + 0.0722 * lin(5)
  return 1.05 / (l + 0.05)
}
