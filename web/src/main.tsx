import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/inter'
import './index.css'
import App from './App.tsx'
import { applyStoredAccent } from './accent'

// Light by default; dark only if the user chose it (see the header toggle).
try {
  if (localStorage.getItem('cpm-theme') === 'dark')
    document.documentElement.dataset.theme = 'dark'
} catch {
  // storage unavailable: stay light
}

applyStoredAccent()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
