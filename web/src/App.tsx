import { useEffect, useState } from 'react'

type Health = { status: string; version: string }

function App() {
  const [health, setHealth] = useState<Health | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/health')
      .then((res) => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json() as Promise<Health>
      })
      .then(setHealth)
      .catch((err: unknown) => setError(String(err)))
  }, [])

  return (
    <main>
      <h1>CaddyProxyManager</h1>
      {health && (
        <p>
          Server: {health.status} (version {health.version})
        </p>
      )}
      {error && <p role="alert">Could not reach the CPM server: {error}</p>}
      {!health && !error && <p>Checking server…</p>}
    </main>
  )
}

export default App
