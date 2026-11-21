import { useApp } from '../context/AppContext'
import { Head } from '../components/Table'

export default function Origins() {
  const { events } = useApp()
  const blocked = events.filter(event => event.status === 'Blocked')
  return <>
    <Head t="Event sources" s="Blocked events by source across the most recent workspace records."/>
    <ul className="nc max-w-3xl divide-y">
      {(['Live', 'Preview'] as const).map(source => <li key={source} className="flex justify-between p-4 text-sm">
        <span>{source === 'Live' ? 'Protected account endpoint' : 'Simulation lab'}</span>
        <span className="font-mono">{blocked.filter(event => event.source === source).length}</span>
      </li>)}
    </ul>
  </>
}
