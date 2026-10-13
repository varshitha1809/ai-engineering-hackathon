// Typed client for the PHISHDNA FastAPI backend. Every page reads/writes real application state through here.
const BASE = (import.meta.env.VITE_API_BASE as string | undefined) ?? ''
const KEY = import.meta.env.VITE_API_KEY as string | undefined

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers)
  if (KEY) headers.set('X-API-Key', KEY)
  if (init.body && !(init.body instanceof FormData) && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  let res: Response
  try {
    res = await fetch(`${BASE}/api/v1${path}`, { ...init, headers })
  } catch {
    throw new ApiError(0, 'Backend unreachable - is the API running on port 8000?')
  }
  if (!res.ok) {
    let msg = `${res.status} ${res.statusText}`
    try {
      const j = await res.json()
      msg = typeof j.detail === 'string' ? j.detail : Array.isArray(j.detail) ? j.detail.map((d: { msg: string }) => d.msg).join('; ') : msg
    } catch { /* non-JSON error */ }
    throw new ApiError(res.status, msg)
  }
  const ct = res.headers.get('content-type') ?? ''
  return (ct.includes('application/json') ? res.json() : res.text()) as Promise<T>
}

export const get = <T,>(p: string) => request<T>(p)
export const post = <T,>(p: string, body?: unknown) =>
  request<T>(p, { method: 'POST', body: body instanceof FormData ? body : body === undefined ? undefined : JSON.stringify(body) })
export const patch = <T,>(p: string, body: unknown) => request<T>(p, { method: 'PATCH', body: JSON.stringify(body) })
export const del = <T,>(p: string) => request<T>(p, { method: 'DELETE' })
export const downloadUrl = (p: string) => `${BASE}/api/v1${p}`

export async function download(p: string, filename: string) {
  const headers = new Headers()
  if (KEY) headers.set('X-API-Key', KEY)
  const res = await fetch(downloadUrl(p), { headers })
  if (!res.ok) throw new ApiError(res.status, `export failed (${res.status})`)
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

// ---------------------------------------------------------------- types
export type Verdict = 'LIKELY_PHISHING' | 'SUSPICIOUS_REVIEW' | 'AI_INJECTION_SUSPECTED' | 'NO_STRONG_INDICATORS' | 'INSUFFICIENT_EVIDENCE'

export interface Finding {
  finding_id: string; category: string; component: string; severity: string; title: string; observed_value: string
  source_location: string; method: string; version: string; confidence: number; status: 'observed' | 'inferred' | 'unavailable'
  explanation: string; timestamp: string; related_indicator_ids: number[]; related_finding_ids: string[]
  span: { field: 'subject' | 'body'; start: number; end: number } | null; tags: string[]
}
export interface GraphNode { id: string; kind: string; label: string; status: string; evidence: string[]; detail: string }
export interface GraphEdge { source: string; target: string; relation: string; evidence: string[]; status: string }
export interface Reconstruction {
  nodes: GraphNode[]; edges: GraphEdge[]; has_attack_story: boolean; narrative: string; caveat: string
  timeline: { stage: string; kind: string; status: string; items: { label: string; evidence: string[]; status: string; detail: string }[] }[]
  verification_steps: { step: string; resolves_uncertainty_in: string[] }[]
  attack_mapping: { id: string; name: string; basis: string }[]
}
export interface ModelOut {
  score: number; threshold: number; predicted_label: number; margin: number; latency_ms: number
  top_contributions: { feature: string; type: string; contribution: number; direction: string }[]
  model_version: string; explanation_method: string
}
export interface CaseRow {
  id: string; analysis_id: string; status: string; priority: string; priority_score: number; assignee: string | null
  created_at: string; updated_at: string; notes_json: { ts: string; author: string; text: string }[]; resolution: string | null
}
export interface Analysis {
  id: string; created_at: string; input_source: string; data_label: string; batch_id: string | null
  parsed: Record<string, any>; verdict: Verdict; verdict_label: string; risk_score: number; score_semantics: string
  decision: { verdict: Verdict; risk_score: number; strong_groups: string[]; decision_reasons: string[]; flags: string[]; policy: Record<string, number> }
  uncertainty: { level: 'low' | 'medium' | 'high'; reasons: string[] }
  impact: { potential_impact: string; impact_actions: string[]; priority: string; priority_score: number; rationale: string }
  strengths: Record<string, number>; model: ModelOut | null
  tactics: Record<string, string[]>; actions: Record<string, string[]>; findings: Finding[]
  reconstruction: Reconstruction
  explanation: { user: string; analyst: { decision_reasons: string[]; group_strengths: { group: string; strength: number; weight: number }[]; top_findings: string[]; note: string } }
  recommendations: { action: string; text: string; evidence?: string[] }[]
  threat_intel: { stats: Record<string, any>; results: { indicator_type: string; value: string; provider: string; verdict: string; source: string; checked_at: string; detail: string; location: string }[] }
  stage_status: Record<string, { status: string; detail?: string; ms?: number }>
  versions: { model: string; rules: string; fusion: string }
  latency_ms: number; body_text: string; preview: string; local_state: string
  original: { verdict: Verdict; risk_score: number }
  case: CaseRow | null; campaigns: { id: string; label: string; severity: string; member_count: number }[]
  related_edges: { id: number; other: string; edge_type: string; strength: number; strength_label: string; explanation: string; evidence_json: { indicator_type: string; value: string }[] }[]
  indicators: { id: number; type: string; display_value: string; reputation: string | null; reputation_source: string | null; sightings: number; location: string }[]
  history: { id: number; created_at: string; reason: string; verdict: string; risk_score: number; model_version: string; rules_version: string }[]
  feedback: { id: number; label: string; notes: string; reviewer: string; created_at: string; original_verdict: string }[]
  raw_retained: boolean
}
export interface AnalysisRow {
  id: string; created_at: string; input_source: string; data_label: string; subject: string; from_addr: string
  verdict: Verdict; verdict_label: string; risk_score: number; priority: string; priority_score: number; local_state: string
  model_version: string; batch_id: string | null
}
export interface Campaign {
  id: string; created_at: string; updated_at: string; label: string; severity: string; severity_score: number; member_count: number
  first_seen: string; last_seen: string; low_and_slow: number
  summary_json: { label: string; edge_types: Record<string, number>; shared_evidence: [string, number][]; requested_actions: string[]
    tactics: string[]; max_member_risk: number; mean_member_risk: number; max_edge_strength: number; verdicts: Record<string, number>
    span_days: number; high_impact: boolean; low_and_slow_reason: string; attribution_note: string }
}
export interface CampaignEdge {
  id: number; campaign_id: string | null; src: string; dst: string; edge_type: string; strength: number; strength_label: string
  evidence_json: { indicator_type: string; value: string }[]; explanation: string; created_at: string
}
export interface Metrics { n: number; positives: number; tp: number; fp: number; tn: number; fn: number; precision: number; recall: number; f1: number; fpr: number | null; pr_auc?: number }
export interface EvalRun {
  id: string; suite: string; status: string; progress: number; total: number; started_at: string; finished_at: string | null
  params_json: Record<string, any>; model_version: string; rules_version: string; fusion_version: string; error: string | null
  metrics_json?: any; summary?: { overall: { baseline: Metrics | null; hybrid: Metrics }; counts: Record<string, number> } | null
}
