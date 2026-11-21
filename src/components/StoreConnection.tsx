import { useEffect, useState } from 'react'
import { createStoreKey, errorMessage, getStoreConnection } from '../services/api'

export default function StoreConnection() {
  const [configured,setConfigured] = useState<boolean|null>(null)
  const [key,setKey] = useState('')
  const [busy,setBusy] = useState(false)
  const [copied,setCopied] = useState(false)
  const [failure,setFailure] = useState('')

  useEffect(()=>{
    const controller = new AbortController()
    getStoreConnection(controller.signal).then(result=>setConfigured(result.configured)).catch(error=>{
      if (!controller.signal.aborted) setFailure(errorMessage(error))
    })
    return ()=>controller.abort()
  },[])

  async function generate() {
    setBusy(true)
    setFailure('')
    setCopied(false)
    try {
      setKey(await createStoreKey())
      setConfigured(true)
    } catch(error) {
      setFailure(errorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  return <section className="nc mt-4 max-w-lg space-y-3 p-4 sm:p-6">
    <h2 className="font-serif text-2xl">M.A-HIJAB connection</h2>
    <p className="text-sm text-muted">Give the store’s Express server a private key to report blocked login requests.</p>
    {configured && <p className="text-sm text-muted">A key exists. Replacing it invalidates the previous key.</p>}
    {key && <div className="space-y-2">
      <label htmlFor="store-key" className="block text-sm">Server integration key</label>
      <input id="store-key" readOnly value={key} className="w-full font-mono" onFocus={event=>event.target.select()}/>
      <button type="button" onClick={async()=>{
        try { await navigator.clipboard.writeText(key); setCopied(true) } catch { setFailure('Select and copy the key from the field.') }
      }} className="rounded-md border px-3 py-2 text-sm">{copied?'Copied':'Copy key'}</button>
      <p className="text-xs text-muted">Set it as CYBERGUARD_STORE_KEY in the store’s server environment. This key is shown once.</p>
    </div>}
    {configured!==null && <button disabled={busy} onClick={()=>void generate()} className="rounded-md bg-accent px-4 py-2 text-sm disabled:opacity-60">
      {busy?'Creating…':configured?'Replace key':'Create integration key'}
    </button>}
    {failure && <p role="alert" className="text-sm text-bad">{failure}</p>}
  </section>
}
