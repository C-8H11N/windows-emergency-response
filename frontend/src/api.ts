import type { GuideCategory, Health, ScanStatus } from './types'

async function json<T>(url: string, init?: RequestInit): Promise<T> {
  const res = await fetch(url, { headers: { 'Content-Type': 'application/json' }, ...init })
  if (!res.ok) throw new Error(await res.text())
  return res.json()
}

export const api = {
  health: () => json<Health>('/api/health'),
  guide: () => json<{ categories: GuideCategory[]; safe_notice: string }>('/api/guide'),
  startScan: (modules?: string[]) => json<ScanStatus>('/api/scan/start', { method: 'POST', body: JSON.stringify({ modules }) }),
  status: () => json<ScanStatus>('/api/scan/status'),
  cancelScan: () => json<ScanStatus>('/api/scan/cancel', { method: 'POST' }),
  setIntel: (mode: string, confirm_external = false) => json('/api/threat-intel/config', { method: 'POST', body: JSON.stringify({ mode, confirm_external }) }),
  killProcess: (pid: number, reason: string) => json('/api/processes/kill', { method: 'POST', body: JSON.stringify({ pid, confirm: true, reason }) }),
  openFileLocation: (path: string) => json('/api/files/open-location', { method: 'POST', body: JSON.stringify({ path }) }),
  downloadReport: () => { window.location.href = '/api/report/html' }
}
