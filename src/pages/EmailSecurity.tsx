import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Head } from '../components/Table'
import { useApp } from '../context/AppContext'
import {
  checkEmailSecurity, disconnectEmail, errorMessage, getEmailSecurity, startEmailConnection,
  type EmailSecurityStatus,
} from '../services/api'

export default function EmailSecurity() {
  const { refresh } = useApp()
  const [params] = useSearchParams()
  const [status, setStatus] = useState<EmailSecurityStatus | null>(null)
  const [busy, setBusy] = useState(false)
  const [problem, setProblem] = useState('')
  const [loadError, setLoadError] = useState('')
  const [scanRequested, setScanRequested] = useState(false)
  const [reload, setReload] = useState(0)

  useEffect(() => {
    const controller = new AbortController()
    let timer: number
    let next: EmailSecurityStatus | undefined
    const load = async () => {
      try {
        next = await getEmailSecurity(controller.signal)
        if (!controller.signal.aborted) {
          setStatus(next)
          setLoadError('')
        }
      } catch (failure) {
        if (!controller.signal.aborted) setLoadError(errorMessage(failure))
      } finally {
        if (!controller.signal.aborted && (next?.connection || !next)) {
          timer = window.setTimeout(load, 8000)
        }
      }
    }
    void load()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [reload])

  const run = async (action: 'connect' | 'check' | 'disconnect') => {
    setBusy(true)
    setProblem('')
    try {
      if (action === 'connect') {
        const { url } = await startEmailConnection()
        window.location.assign(url)
        return
      }
      if (action === 'check') {
        await checkEmailSecurity()
        setScanRequested(true)
      } else {
        await disconnectEmail()
        setScanRequested(false)
        setStatus(previous => previous ? { ...previous, connection: null, alerts: [] } : null)
        await refresh()
      }
      setReload(value => value + 1)
    } catch (failure) {
      setProblem(errorMessage(failure))
    } finally {
      setBusy(false)
    }
  }

  const connection = status?.connection
  return <>
    <Head t="Email security" s="Review security notices Google sends to your connected Gmail inbox."/>
    {params.get('oauth') === 'failed' && !connection && <p role="alert" className="mb-4 text-bad">Gmail authorization did not finish. Try connecting again.</p>}
    {(loadError || problem) && <p role="alert" className="mb-4 text-bad">{problem || loadError}</p>}
    <section className="nc max-w-3xl space-y-4 p-5">
      {!status && !loadError && <p role="status">Checking connection…</p>}
      {status && !status.configured && <p className="text-bronze">Gmail monitoring is unavailable until Google OAuth is configured on the server.</p>}
      {connection ? <>
        <div><div className="text-xs text-muted">Connected Gmail</div><div className="break-all font-semibold">{connection.email}</div></div>
        {connection.failure && <p role="alert" className="text-bad">{connection.failure}</p>}
        <p className="text-sm text-muted">{connection.last_checked
          ? `Last successful check ${new Date(connection.last_checked).toLocaleString()}`
          : 'Waiting for the first successful check.'}</p>
        {scanRequested && <p role="status" className="text-sm text-muted">Check requested. Gmail is checked up to once every five minutes.</p>}
        <div className="flex flex-wrap gap-3">
          <button disabled={busy || !status?.configured} onClick={() => run('check')} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50">Check for alerts</button>
          <button disabled={busy} onClick={() => run('disconnect')} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50">Disconnect Gmail</button>
          {connection.failure && <button disabled={busy || !status?.configured} onClick={() => run('connect')} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50">Reconnect Gmail</button>}
        </div>
      </> : status?.configured && <>
        <p className="text-sm text-muted">Approve read-only Gmail access in Google. SentraTrace checks headers on supported Google security notices and saves the notice type and time.</p>
        <button disabled={busy} onClick={() => run('connect')} className="rounded-md border px-3 py-2 text-sm disabled:opacity-50">Connect Gmail</button>
      </>}
      <p className="text-sm text-muted">Google may send only some security events to email. Check your Google Account for the complete activity Google makes available.</p>
      <a href="https://myaccount.google.com/notifications" target="_blank" rel="noreferrer" className="inline-block text-sm underline">Review activity in Google Account</a>
    </section>
    {connection && <section className="nc mt-6 max-w-3xl p-5">
      <h2 className="font-serif text-2xl">Recent Gmail alerts</h2>
      {status?.alerts.length ? <ul className="mt-3 divide-y">
        {status.alerts.map(alert => <li key={alert.id} className="py-3">
          <strong>{alert.kind}</strong>
          <div className="text-sm text-muted">{new Date(alert.timestamp).toLocaleString()}</div>
        </li>)}
      </ul> : <p className="mt-3 text-sm text-muted">No matching security emails have been found.</p>}
    </section>}
  </>
}
