import { useState } from 'react'
import { errorMessage, inspect, playgroundPaths } from '../services/api'
import { useApp } from '../context/AppContext'
import { Head } from '../components/Table'

export default function Playground() {
  const { refresh } = useApp()
  const [index, setIndex] = useState(0)
  const [output, setOutput] = useState('Pick an endpoint and send a request.')
  const [busy, setBusy] = useState(false)

  const send = async () => {
    setBusy(true)
    const path = playgroundPaths[index]
    const started = performance.now()
    try {
      const response = await inspect(path)
      setOutput(`${response.status}  ${Math.round(performance.now() - started)} ms\n\n${JSON.stringify(response.data, null, 2)}`)
      if (path === '/accounts/me') await refresh()
    } catch (error) {
      setOutput(errorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  return <>
    <Head t="API playground" s="Inspect responses from your SentraTrace backend."/>
    <div className="flex min-w-0 flex-col gap-3 sm:flex-row sm:flex-wrap">
      <select aria-label="Endpoint" value={index} onChange={event => setIndex(Number(event.target.value))} className="w-full sm:w-auto">
        {playgroundPaths.map((path, position) => <option key={path} value={position}>GET /api{path}</option>)}
      </select>
      <button disabled={busy} onClick={send} className="w-full rounded-md bg-accent px-5 py-2 font-semibold sm:w-auto">{busy ? 'Sending…' : 'Send request'}</button>
    </div>
    <pre className="nc mt-6 min-h-[220px] overflow-x-auto whitespace-pre-wrap p-4 font-mono text-xs text-info">{output}</pre>
  </>
}
