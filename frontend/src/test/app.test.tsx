import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { VerdictBadge } from '../components/ui'
import Analyze from '../pages/Analyze'
import Evidence from '../pages/Evidence'
import Landing from '../pages/Landing'
import Lab from '../pages/Lab'

type Handler = (url: string, init?: RequestInit) => unknown
let handler: Handler
const calls: { url: string; init?: RequestInit }[] = []

function json(body: unknown, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }))
}

beforeEach(() => {
  calls.length = 0
  vi.stubGlobal('fetch', vi.fn((url: string, init?: RequestInit) => {
    calls.push({ url, init })
    const r = handler(url, init)
    return r instanceof Promise ? r : json(r)
  }))
  // jsdom lacks these browser APIs used by the particle canvas
  HTMLCanvasElement.prototype.getContext = vi.fn(() => null) as never
  window.matchMedia = vi.fn(() => ({ matches: true })) as never
})
afterEach(() => vi.unstubAllGlobals())

const renderAt = (path: string, el: React.ReactNode, routePath = path) =>
  render(<MemoryRouter initialEntries={[path]}><Routes><Route path={routePath} element={el} /><Route path="/app/analyses/:id" element={<div>detail page</div>} /></Routes></MemoryRouter>)

describe('Analyze page', () => {
  it('validates empty input without calling the API', async () => {
    handler = () => ({})
    renderAt('/app/analyze', <Analyze />)
    await userEvent.click(screen.getByRole('button', { name: /run analysis/i }))
    expect(screen.getByRole('alert')).toHaveTextContent(/paste the email text first/i)
    expect(calls.filter(c => c.url.includes('/analyze'))).toHaveLength(0)
  })

  it('submits pasted text as multipart form data and opens the result', async () => {
    handler = url => (url.endsWith('/api/v1/analyze') ? { id: 'A-1' } : {})
    renderAt('/app/analyze', <Analyze />)
    await userEvent.type(screen.getByLabelText(/email content/i), 'From: a@b.test{enter}Subject: hi{enter}{enter}verify your password')
    expect(screen.getByText(/header block detected/i)).toBeInTheDocument()
    await userEvent.click(screen.getByRole('button', { name: /run analysis/i }))
    await waitFor(() => expect(screen.getByText('detail page')).toBeInTheDocument())
    const c = calls.find(x => x.url.endsWith('/api/v1/analyze'))!
    expect(c.init?.method).toBe('POST')
    expect((c.init?.body as FormData).get('text')).toContain('verify your password')
  })

  it('shows backend validation errors instead of a result', async () => {
    handler = url => (url.endsWith('/api/v1/analyze') ? json({ detail: 'could not parse input: input is empty' }, 422) : {})
    renderAt('/app/analyze', <Analyze />)
    await userEvent.type(screen.getByLabelText(/email content/i), 'x')
    await userEvent.click(screen.getByRole('button', { name: /run analysis/i }))
    expect(await screen.findByRole('alert')).toHaveTextContent(/could not parse input/i)
  })

  it('rejects unsupported upload types client-side', async () => {
    handler = () => ({})
    renderAt('/app/analyze', <Analyze />)
    await userEvent.click(screen.getByRole('tab', { name: /upload/i }))
    const input = screen.getByLabelText(/choose .eml file/i)
    await userEvent.upload(input, new File(['%PDF'], 'doc.pdf', { type: 'application/pdf' }), { applyAccept: false })
    expect(screen.getByRole('alert')).toHaveTextContent(/unsupported file type/i)
  })
})

describe('Verdict badge', () => {
  it('carries a text label, not colour alone', () => {
    render(<VerdictBadge verdict="LIKELY_PHISHING" />)
    expect(screen.getByText('High risk')).toBeInTheDocument()
  })
})

describe('Evidence explorer', () => {
  it('links findings to highlighted source spans', async () => {
    const body = 'Please verify your password today.'
    handler = () => ({
      id: 'A-9', verdict: 'SUSPICIOUS_REVIEW', verdict_label: 'Suspicious — review', parsed: { subject: 'Hi' }, body_text: body, indicators: [],
      findings: [{ finding_id: 'F001', title: 'Requested action: provide credentials', category: 'action.provide_credentials', component: 'intent',
        severity: 'high', observed_value: 'verify your password', source_location: 'body[7:27]', method: 'rule', version: 'rules-1', confidence: 0.6,
        status: 'observed', explanation: 'x', timestamp: 't', related_indicator_ids: [], related_finding_ids: [], span: { field: 'body', start: 7, end: 27 }, tags: [] }],
    })
    renderAt('/app/evidence/A-9', <Evidence />, '/app/evidence/:id')
    const mark = await screen.findByText('verify your password', { selector: 'mark' })
    await userEvent.click(mark)
    expect(mark).toHaveClass('active')
    expect(screen.getByText(/evidence strength, not a probability/i)).toBeInTheDocument()
  })
})

describe('Robustness lab', () => {
  it('starts a real benchmark run via the API', async () => {
    handler = (url, init) => {
      if (url.endsWith('/evaluations/run') && init?.method === 'POST') return { id: 'EVAL-1', status: 'queued' }
      if (url.endsWith('/evaluations')) return []
      if (url.includes('/evaluations/EVAL-1')) return { id: 'EVAL-1', status: 'running', progress: 3, total: 10 }
      return {}
    }
    render(<MemoryRouter initialEntries={['/app/lab']}><Routes><Route path="/app/lab" element={<Lab />} /><Route path="/app/lab/:runId" element={<Lab />} /></Routes></MemoryRouter>)
    await userEvent.click(await screen.findByRole('button', { name: /run benchmark/i }))
    await waitFor(() => expect(calls.some(c => c.url.endsWith('/evaluations/run'))).toBe(true))
    const body = JSON.parse(calls.find(c => c.url.endsWith('/evaluations/run'))!.init!.body as string)
    expect(body).toMatchObject({ suite: 'fixtures', variants: true })
    expect(await screen.findByRole('progressbar')).toBeInTheDocument()
  })
})

describe('Landing page', () => {
  it('never shows invented metrics when the backend is unreachable', async () => {
    handler = () => Promise.reject(new TypeError('network'))
    render(<MemoryRouter><Landing /></MemoryRouter>)
    expect(screen.getByText(/decoded to/i)).toBeInTheDocument()
    expect(await screen.findByText(/evaluation results are unavailable/i)).toBeInTheDocument()
    expect(screen.queryByText(/\d+\.\d%/)).not.toBeInTheDocument()
  })
})
