import { useEffect, useState } from 'react'
import { errorMessage, getPolicies } from '../services/api'
import { Head } from '../components/Table'

export default function Policies() {
  const [policies, setPolicies] = useState<string[]>([])
  const [error, setError] = useState('')
  useEffect(() => {
    const controller = new AbortController()
    getPolicies(controller.signal).then(setPolicies).catch(failure => {
      if (!controller.signal.aborted) setError(errorMessage(failure))
    })
    return () => controller.abort()
  }, [])
  return <>
    <Head t="Security policies" s="Rules currently enforced by the backend."/>
    {error ? <p role="alert" className="text-bad">{error}</p>
      : policies.length ? <ul className="nc max-w-2xl divide-y">
        {policies.map(policy => <li key={policy} className="p-4 text-sm">{policy}</li>)}
      </ul> : <p role="status" className="text-muted">Loading policies…</p>}
  </>
}
