import { useEffect, useState } from 'react'
import { getHealth, playgroundPaths } from '../services/api'
import { Head } from '../components/Table'

export default function Agents() {
  const [health, setHealth] = useState({ status: 'Checking…', latency: '—', engine: '—', database: '—', authentication: '—' })
  useEffect(() => {
    const controller = new AbortController()
    let timer: number
    const check = async () => {
      const started = performance.now()
      try {
        const response = await getHealth(controller.signal)
        setHealth({ status: response.status === 'ok' ? 'Connected' : 'Unavailable',
          latency: `${Math.round(performance.now() - started)} ms`, engine: response.engine,
          database: response.database, authentication: response.authentication })
      } catch {
        if (!controller.signal.aborted) setHealth({ status: 'Unavailable', latency: '—', engine: '—', database: '—', authentication: '—' })
      } finally {
        if (!controller.signal.aborted) timer = window.setTimeout(check, 5000)
      }
    }
    void check()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [])

  return <>
    <Head t="API infrastructure" s="Checks the FastAPI service and its database connection."/>
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
      {Object.entries({ Connection: health.status, Database: health.database, Authentication: health.authentication, Latency: health.latency, Engine: health.engine }).map(([label, value]) =>
        <div key={label} className="nc min-w-0 p-4 sm:p-6">
          <div className="text-sm text-muted">{label}</div><div className="mt-2 font-serif text-2xl">{value}</div>
        </div>)}
    </div>
    <h2 className="mb-4 mt-10 font-serif text-2xl">Defense rules</h2>
    <ul className="nc divide-y text-sm">
      <li className="p-4">Account reads verify the signed-in identity against the requested account.</li>
      <li className="p-4">Sign-in checks the rate limit before verifying credentials.</li>
      <li className="p-4">Account access decisions are recorded in the workspace.</li>
    </ul>
    <h2 className="mb-4 mt-10 font-serif text-2xl">Playground endpoints</h2>
    <ul className="nc divide-y font-mono text-xs">{playgroundPaths.map(path => <li key={path} className="p-3">GET /api{path}</li>)}</ul>
  </>
}
