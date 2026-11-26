import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/inter'
import '@fontsource/outfit/700.css'
import './hsl-ui/tokens.css'
import './hsl-ui/shell.css'
import './hsl-ui/auth.css'
import './hsl-ui/suite.js'
import './index.css'
import App from './App.tsx'
import { applyStoredAccent } from './accent'

// Light by default; dark only if the user turns it on in the user menu. The kit keeps the choice
// under hsl-suite-theme; bring over the old Switchyard setting once.
window.HSLSuite.theme.migrate(['cpm-theme'])

applyStoredAccent()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
