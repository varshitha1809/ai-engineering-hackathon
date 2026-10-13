/// <reference types="vitest/config" />
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

const API = process.env.PHISHDNA_API_URL ?? 'http://127.0.0.1:8000'

// Dev and preview servers proxy /api to the FastAPI backend, so the app always talks to the real API.
export default defineConfig({
  plugins: [react()],
  server: { port: 5173, proxy: { '/api': API } },
  preview: { port: 4173, proxy: { '/api': API } },
  test: { environment: 'jsdom', setupFiles: ['./src/test/setup.ts'], css: false },
})
