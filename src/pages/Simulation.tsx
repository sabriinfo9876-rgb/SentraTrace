import { useState } from 'react'
import { errorMessage, simulate } from '../services/api'
import { useApp } from '../context/AppContext'
import type { SimResult } from '../types/security'

const labs = [
  { kind: 'bola' as const, title: 'Object ownership policy', description: 'See how the ownership rule handles preset identities that do not match.' },
  { kind: 'brute-force' as const, title: 'Sign-in rate limit', description: 'See how the rate-limit rule handles a preset counter at the threshold.' },
]

function Lab({ lab }: { lab: typeof labs[number] }) {
  const { refresh } = useApp()
  const [result, setResult] = useState<SimResult | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const run = async () => {
    setBusy(true)
    setResult(null)
    setError('')
    try {
      setResult(await simulate(lab.kind))
      await refresh()
    } catch (failure) {
      setError(errorMessage(failure))
    } finally {
      setBusy(false)
    }
  }

  return <section className="min-w-0 space-y-5 border-t pt-6">
    <h2 className="break-words font-serif text-2xl sm:text-3xl">{lab.title}</h2>
    <p className="max-w-md text-sm text-muted">{lab.description}</p>
    <button disabled={busy} onClick={run} className="bg-accent rounded-[3px] px-4 py-2 font-semibold disabled:opacity-60">
      {busy ? 'Evaluating…' : 'Run policy preview'}
    </button>
    {error && <p role="alert" className="text-sm text-bad">{error}</p>}
    {result && <div role="status" className="space-y-3 text-sm">
      <div>Risk score <span className="font-mono text-accent">{result.risk_score}</span></div>
      <p>{result.explanation}</p>
      <p>Decision <b>{result.defender_action}</b></p>
      <p>{result.remediation}</p>
      <pre className="overflow-x-auto border bg-elev p-3 font-mono text-xs">{JSON.stringify(result.raw, null, 2)}</pre>
    </div>}
  </section>
}

export default function Simulation() {
  return <div className="space-y-8 sm:space-y-10">
    <h1 className="font-serif text-3xl sm:text-4xl lg:text-5xl">Simulation lab</h1>
    <p className="text-sm text-muted">Policy previews evaluate preset data and appear in your workspace as Preview events.</p>
    <div className="grid min-w-0 gap-8 lg:grid-cols-2 lg:gap-12">{labs.map(lab => <Lab key={lab.kind} lab={lab}/>)}</div>
  </div>
}
