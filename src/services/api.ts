import axios, { type AxiosResponse } from 'axios'
import type { SecurityEvent, SimResult, Stats } from '../types/security'

export interface User { id: string; email: string; name: string }
export interface Notif { id: string; msg: string; t: string; read: boolean }
export interface Audit { t: string; msg: string }
export interface Workspace {
  stats: Stats
  events: SecurityEvent[]
  notifs: Notif[]
  audit: Audit[]
}

const http = axios.create({
  baseURL: '/api',
  timeout: 10000,
  headers: { 'X-CyberGuard-Client': '1' },
})

const workspaceHeader = 'X-CyberGuard-Workspace'
export const SESSION_INVALID = 'cyberguard-session-invalid'
let workspaceUserId: string | null = null

export function bindWorkspace(userId: string | null) {
  workspaceUserId = userId
}

http.interceptors.request.use(config => {
  const isPublic = ['/auth/me', '/auth/login', '/auth/signup', '/auth/google/status', '/auth/google/start', '/health'].includes(config.url ?? '')
  if (isPublic) return config
  if (!workspaceUserId) throw new axios.CanceledError('No active workspace.')
  config.headers.set(workspaceHeader, workspaceUserId)
  return config
}, undefined, { synchronous: true })

function signalInvalidSession(response: AxiosResponse) {
  if (response.status === 401 && workspaceUserId && response.config.headers.get(workspaceHeader) === workspaceUserId) {
    window.dispatchEvent(new Event(SESSION_INVALID))
  }
}

http.interceptors.response.use(response => {
  signalInvalidSession(response)
  return response
}, error => {
  if (axios.isAxiosError(error) && error.response) signalInvalidSession(error.response)
  return Promise.reject(error)
})

export function isUnauthorized(error: unknown) {
  return axios.isAxiosError(error) && error.response?.status === 401
}

export function errorMessage(error: unknown) {
  if (axios.isAxiosError(error)) {
    const detail = error.response?.data?.detail
    if (typeof detail === 'string') return detail
    if (!error.response || error.response.status >= 500) {
      return 'Cannot reach FastAPI. Check that the backend is running, then retry.'
    }
  }
  return 'The request could not be completed. Try again.'
}

export const getSession = async (signal: AbortSignal) =>
  (await http.get<User>('/auth/me', { signal })).data
export const signIn = async (email: string, password: string) =>
  (await http.post<User>('/auth/login', { email, password })).data
export const signUp = async (name: string, email: string, password: string) =>
  (await http.post<User>('/auth/signup', { name, email, password })).data
export const signOut = () => http.post('/auth/logout')
export const getWorkspace = async () => (await http.get<Workspace>('/workspace')).data
export const getHealth = async (signal: AbortSignal) =>
  (await http.get<{ status: string; engine: string; database: string; authentication: string }>('/health', { signal })).data
export const getPolicies = async (signal: AbortSignal) =>
  (await http.get<string[]>('/policies', { signal })).data
export const simulate = async (kind: 'bola' | 'brute-force') =>
  (await http.post<SimResult>(`/simulate/${kind}`)).data
export const updateNotifications = (action: 'read' | 'clear') =>
  http.post(`/notifications/${action}`)

export const playgroundPaths = ['/health', '/workspace', '/accounts/me', '/policies'] as const
export const inspect = (path: typeof playgroundPaths[number]) =>
  http.get(path, { validateStatus: () => true })

export interface EmailSecurityStatus {
  configured: boolean
  connection: { email: string; last_checked: string | null; failure: string | null; next_check: number } | null
  alerts: { id: string; kind: string; timestamp: string }[]
}

export const getEmailSecurity = async (signal?: AbortSignal) =>
  (await http.get<EmailSecurityStatus>('/email-security', { signal })).data
export const startEmailConnection = async () =>
  (await http.post<{ url: string }>('/email-security/connect')).data
export const checkEmailSecurity = async () =>
  (await http.post<EmailSecurityStatus>('/email-security/check')).data
export const disconnectEmail = () => http.post('/email-security/disconnect')

export const getGoogleLogin = async (signal: AbortSignal) =>
  (await http.get<{ configured: boolean }>('/auth/google/status', { signal })).data
export const getGoogleLink = async (signal: AbortSignal) =>
  (await http.get<{ configured: boolean; email: string | null }>('/auth/google/link', { signal })).data
export const startGoogleLogin = async (link = false) =>
  (await http.post<{ url: string }>(link ? '/auth/google/link' : '/auth/google/start')).data.url

export type CopilotLanguage = 'en' | 'roman' | 'ur'
export type CopilotMode = 'workspace' | 'gemini' | 'fallback'
export const askCopilot = async (message: string, language: CopilotLanguage) =>
  (await http.post<{text: string; mode: CopilotMode}>('/copilot', { message, language })).data
export const getStoreConnection = async (signal: AbortSignal) =>
  (await http.get<{configured: boolean}>('/integrations/ma-hijab', {signal})).data
export const createStoreKey = async () =>
  (await http.post<{key: string}>('/integrations/ma-hijab/key')).data.key
