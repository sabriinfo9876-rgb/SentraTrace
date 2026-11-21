import { useState } from 'react'
import { useApp } from '../context/AppContext'
import { errorMessage, updateNotifications } from '../services/api'
import { Head } from '../components/Table'

export default function Notifications() {
  const { notifs, refresh } = useApp()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const mark = async (action: 'read' | 'clear') => {
    setBusy(true)
    setError('')
    try {
      await updateNotifications(action)
      await refresh()
    } catch (failure) {
      setError(errorMessage(failure))
    } finally {
      setBusy(false)
    }
  }

  return <>
    <Head t="Notifications" s="Blocked decisions and connected Gmail security alerts."/>
    <div className="mb-6 flex flex-wrap gap-3">
      <button disabled={busy || !notifs.some(item => !item.read)} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50" onClick={() => mark('read')}>Mark all read</button>
      <button disabled={busy || !notifs.length} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50" onClick={() => mark('clear')}>Clear all</button>
    </div>
    {error && <p role="alert" className="mb-4 text-sm text-bad">{error}</p>}
    <ul className="nc max-w-2xl divide-y">
      {notifs.map(item => <li key={item.id} className="flex items-start justify-between gap-3 p-4 text-sm">
        <span className="flex min-w-0 items-start gap-3 break-words">
          {!item.read && <i aria-label="Unread" className="mt-1 h-2 w-2 shrink-0 rounded-full bg-[#D65CEB]"/>}{item.msg}
        </span>
        <span className="shrink-0 font-mono text-xs text-muted">{new Date(item.t).toLocaleTimeString()}</span>
      </li>)}
      {!notifs.length && <li className="p-8 text-center text-muted">No notifications yet.</li>}
    </ul>
  </>
}
