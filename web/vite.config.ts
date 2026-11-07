import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // During `npm run dev`, send API calls to the Go server (`make run`).
    proxy: { '/api': 'http://localhost:8080' },
  },
})
