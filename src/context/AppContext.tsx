import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from 'react'
import * as api from '../services/api'
import type { SecurityEvent, Stats } from '../types/security'

export type Theme = 'dark' | 'light'
export const readTheme = (): Theme => localStorage.getItem('cg_theme') === 'dark' ? 'dark' : 'light'
const POLL_INTERVALS = [4000, 8000, 15000, 30000]
const SESSION_CHANGE = 'cg_session_change'

function notifyOtherTabs() {
  localStorage.setItem(SESSION_CHANGE, String(performance.timeOrigin + performance.now()))
}
interface Context {
  events: SecurityEvent[]
  stats: Stats | null
  notifs: api.Notif[]
  audit: api.Audit[]
  refresh: () => Promise<void>
  refreshing: boolean
  refreshError: string | null
  lastUpdated: Date | null
  poll: number
  setPoll: (seconds: number) => void
  theme: Theme
  toggleTheme: () => void
  toast: string | null
  notify: (message: string) => void
  authed: boolean
  checkingSession: boolean
  sessionError: string | null
  login: (user: api.User) => void
  logout: () => Promise<void>
}

const AppContext = createContext<Context>(null!)
export const useApp = () => useContext(AppContext)

export function AppProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<api.User | null>(null)
  const [checkingSession, setCheckingSession] = useState(true)
  const [sessionError, setSessionError] = useState<string | null>(null)
  const [workspace, setWorkspace] = useState<api.Workspace | null>(null)
  const [refreshing, setRefreshing] = useState(false)
  const [refreshError, setRefreshError] = useState<string | null>(null)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const toastTimer = useRef<number>()
  const requestVersion = useRef(0)
  const [theme, setTheme] = useState<Theme>(readTheme)
  const [poll, setPoll] = useState(() => {
    const saved = Number(localStorage.getItem('cg_poll'))
    return POLL_INTERVALS.includes(saved) ? saved : 8000
  })

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('cg_theme', theme)
  }, [theme])
  useEffect(() => { localStorage.setItem('cg_poll', String(poll)) }, [poll])

  useEffect(() => {
    const controller = new AbortController()
    // Older builds stored demo passwords and fake session tokens in the browser.
    for (const key of ['cg_users', 'cg_token', 'cg_notifs', 'cg_audit', 'cg_pol', 'cg_api', 'cg_demo']) {
      localStorage.removeItem(key)
    }
    api.getSession(controller.signal)
      .then(account => {
        if (controller.signal.aborted) return
        api.bindWorkspace(account.id)
        setUser(account)
        if (new URLSearchParams(window.location.search).get('google') === 'signed-in') notifyOtherTabs()
      })
      .catch(error => {
        if (!controller.signal.aborted && !api.isUnauthorized(error)) setSessionError(api.errorMessage(error))
      })
      .finally(() => { if (!controller.signal.aborted) setCheckingSession(false) })
    return () => controller.abort()
  }, [])

  const notify = useCallback((message: string) => {
    window.clearTimeout(toastTimer.current)
    setToast(message)
    toastTimer.current = window.setTimeout(() => setToast(null), 3500)
  }, [])
  useEffect(() => () => window.clearTimeout(toastTimer.current), [])

  const clearSession = useCallback(() => {
    requestVersion.current += 1
    api.bindWorkspace(null)
    window.clearTimeout(toastTimer.current)
    setUser(null)
    setWorkspace(null)
    setLastUpdated(null)
    setRefreshError(null)
    setRefreshing(false)
    setToast(null)
  }, [])

  useEffect(() => {
    const syncTabs = (event: StorageEvent) => {
      if (event.key === SESSION_CHANGE) window.location.reload()
    }
    window.addEventListener('storage', syncTabs)
    window.addEventListener(api.SESSION_INVALID, clearSession)
    return () => {
      window.removeEventListener('storage', syncTabs)
      window.removeEventListener(api.SESSION_INVALID, clearSession)
    }
  }, [clearSession])

  const refresh = useCallback(async () => {
    if (!user) return
    const version = ++requestVersion.current
    setRefreshing(true)
    try {
      const response = await api.getWorkspace()
      if (version !== requestVersion.current) return
      setWorkspace(response)
      setLastUpdated(new Date())
      setRefreshError(null)
    } catch (error) {
      if (version !== requestVersion.current) return
      if (api.isUnauthorized(error)) clearSession()
      else setRefreshError(api.errorMessage(error))
    } finally {
      if (version === requestVersion.current) setRefreshing(false)
    }
  }, [user, clearSession])

  useEffect(() => {
    if (!user) return
    let timer: number
    let active = true
    const pollWorkspace = async () => {
      await refresh()
      if (active) timer = window.setTimeout(pollWorkspace, poll)
    }
    void pollWorkspace()
    return () => { active = false; window.clearTimeout(timer) }
  }, [user, poll, refresh])

  const logout = async () => {
    try {
      await api.signOut()
      clearSession()
      notifyOtherTabs()
    } catch (error) {
      if (!api.isUnauthorized(error)) notify(api.errorMessage(error))
    }
  }

  return <AppContext.Provider value={{
    events: workspace?.events ?? [], stats: workspace?.stats ?? null,
    notifs: workspace?.notifs ?? [], audit: workspace?.audit ?? [],
    refresh, refreshing, refreshError, lastUpdated, poll, setPoll,
    theme, toggleTheme: () => setTheme(current => current === 'dark' ? 'light' : 'dark'),
    toast, notify, authed: !!user, checkingSession, sessionError,
    login: account => {
      api.bindWorkspace(account.id)
      setSessionError(null)
      setUser(account)
      notifyOtherTabs()
    }, logout,
  }}>{children}</AppContext.Provider>
}
