import { useEffect, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useApp } from '../context/AppContext'
import StoreConnection from '../components/StoreConnection'
import { Head } from '../components/Table'
import { errorMessage, getGoogleLink, startGoogleLogin } from '../services/api'

export default function Settings() {
  const { poll, setPoll } = useApp()
  const [params] = useSearchParams()
  const [link, setLink] = useState<{ configured: boolean; email: string | null } | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const result = params.get('google')

  useEffect(() => {
    const controller = new AbortController()
    getGoogleLink(controller.signal).then(info => {
      if (!controller.signal.aborted) setLink(info)
    }).catch(failure => {
      if (!controller.signal.aborted) setError(errorMessage(failure))
    })
    return () => controller.abort()
  }, [])

  const connect = async () => {
    setBusy(true)
    setError('')
    try {
      window.location.assign(await startGoogleLogin(true))
    } catch (failure) {
      setError(errorMessage(failure))
      setBusy(false)
    }
  }

  return <>
    <Head t="Settings" s="Refresh preferences and account sign-in."/>
    <div className="nc max-w-lg p-4 sm:p-6">
      <label className="block text-sm text-muted">Polling interval
        <select className="mt-1 w-full" value={poll} onChange={event => setPoll(Number(event.target.value))}>
          {[4, 8, 15, 30].map(seconds => <option key={seconds} value={seconds * 1000}>{seconds} seconds</option>)}
        </select>
      </label>
    </div>
    {link?.configured && <section className="nc mt-4 max-w-lg space-y-3 p-4 sm:p-6">
      <h2 className="font-serif text-2xl">Google sign-in</h2>
      {result === 'linked' && <p role="status">Google sign-in is linked to this workspace.</p>}
      {link.email
        ? <p className="break-all text-sm text-muted">Linked Google account · {link.email}</p>
        : <button disabled={busy} onClick={connect} className="rounded-md border px-4 py-2 text-sm disabled:opacity-60">{busy ? 'Opening Google…' : 'Link Google account'}</button>}
    </section>}
    <StoreConnection/>
    {(error || result === 'failed' || result === 'already-linked') && <p role="alert" className="mt-3 text-sm text-bad">
      {error || (result === 'already-linked' ? 'That Google account is already linked to another workspace.' : 'Google linking did not finish. Try again.')}
    </p>}
  </>
}
