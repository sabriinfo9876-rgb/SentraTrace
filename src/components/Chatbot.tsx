import { useEffect, useRef, useState } from 'react'
import { Bot, Send, X } from 'lucide-react'
import { askCopilot, errorMessage, type CopilotLanguage, type CopilotMode } from '../services/api'

const prompts = {
  en: ['Summarize incidents', 'Explain account ownership', 'How do I fix login rate-limit issues?'],
  roman: ['Incidents ka khulasa', 'Account ownership samjhao', 'Login rate limit kaise kaam karti hai?'],
  ur: ['واقعات کا خلاصہ', 'اکاؤنٹ کی ملکیت سمجھائیں', 'لاگ اِن کی حد کیسے کام کرتی ہے؟'],
}
const captions: Record<CopilotMode,string> = {
  workspace: 'Workspace help',
  gemini: 'Gemini',
  fallback: 'Workspace help · Gemini unavailable',
}
interface Message { user: boolean; text: string; mode?: CopilotMode }

export default function Chatbot() {
  const [open, setOpen] = useState(false)
  const [language, setLanguage] = useState<CopilotLanguage>('en')
  const [draft, setDraft] = useState('')
  const [messages, setMessages] = useState<Message[]>([])
  const [pending, setPending] = useState(false)
  const [failure, setFailure] = useState('')
  const history = useRef<HTMLDivElement>(null)
  const input = useRef<HTMLInputElement>(null)
  const launcher = useRef<HTMLButtonElement>(null)
  const inFlight = useRef(false)

  useEffect(() => {
    if (open) input.current?.focus({ preventScroll: true })
  }, [open])
  useEffect(() => {
    if (history.current) history.current.scrollTop = history.current.scrollHeight
  }, [messages, open, pending])

  async function send(text: string) {
    const question = text.trim()
    if (!question || inFlight.current) return
    inFlight.current = true
    setPending(true)
    setFailure('')
    try {
      const response = await askCopilot(question, language)
      setMessages(previous => [...previous, {user:true,text:question}, {
        user:false, text:response.text, mode:response.mode,
      }].slice(-40))
      setDraft(current => current === text ? '' : current)
    } catch (error) {
      setFailure(errorMessage(error))
    } finally {
      setPending(false)
      inFlight.current = false
    }
  }

  function close() {
    setOpen(false)
    launcher.current?.focus({ preventScroll: true })
  }

  return <>
    {open && <section aria-label="Security co-pilot" id="security-copilot"
      onKeyDown={event => { if (event.key === 'Escape') close() }}
      className="nc fixed bottom-20 right-4 z-40 flex h-[min(500px,calc(100dvh-6rem))] w-[min(400px,calc(100vw-2rem))] flex-col shadow-[0_0_28px_rgba(138,50,162,.24)] sm:right-6">
      <div className="flex items-start justify-between gap-3 border-b px-4 py-3">
        <div><h2 className="font-serif text-xl">Security co-pilot</h2><p className="text-xs text-muted">Workspace incidents and defensive guidance</p></div>
        <button type="button" aria-label="Close co-pilot" onClick={close} className="rounded p-1 text-muted hover:text-ink"><X size={18}/></button>
      </div>
      <div ref={history} role="log" aria-label="Conversation" className="min-h-0 flex-1 space-y-3 overflow-y-auto p-4 text-sm">
        {!messages.length && <p className="text-muted">Ask about the latest incidents, a security rule, or your reports.</p>}
        {messages.map((message,index) => <div key={index}
          className={`max-w-[92%] whitespace-pre-wrap break-words rounded-lg p-3 [overflow-wrap:anywhere] ${message.user?'ml-auto bg-accent':'bg-elev text-ink'}`} dir="auto">
          {message.text}
          {message.mode && <span className="mt-2 block text-xs text-muted">{captions[message.mode]}</span>}
        </div>)}
        {pending && <p role="status" className="text-muted">Checking…</p>}
      </div>
      <div className="space-y-2 border-t p-3">
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="copilot-language" className="text-xs text-muted">Reply language</label>
          <select id="copilot-language" value={language}
            onChange={event=>setLanguage(event.target.value as CopilotLanguage)}>
            <option value="en">English</option><option value="roman">Roman Urdu</option><option value="ur">اردو</option>
          </select>
        </div>
        {!messages.length && <div className="flex flex-wrap gap-1.5">
          {prompts[language].map(prompt => <button key={prompt} type="button" disabled={pending} onClick={()=>void send(prompt)}
            className="rounded-full border px-2 py-1 text-xs hover:border-accent disabled:opacity-60">{prompt}</button>)}
        </div>}
        {failure && <p role="alert" className="text-sm text-bad">{failure}</p>}
        <form onSubmit={event=>{ event.preventDefault(); void send(draft) }} className="flex gap-2">
          <input ref={input} className="min-w-0 flex-1" aria-label="Message" maxLength={500}
            value={draft} onChange={event=>setDraft(event.target.value)} placeholder="Ask about your workspace"/>
          <button type="submit" disabled={!draft.trim()||pending} className="rounded-md bg-accent px-3 disabled:opacity-60"
            aria-label="Send"><Send size={16}/></button>
        </form>
      </div>
    </section>}
    <button ref={launcher} type="button" onClick={open?close:()=>setOpen(true)}
      aria-label={open?'Hide co-pilot':'Open co-pilot'} aria-expanded={open} aria-controls={open?'security-copilot':undefined}
      className="fixed bottom-5 right-4 z-40 flex h-12 w-12 items-center justify-center rounded-full bg-accent shadow-[0_0_18px_rgba(138,50,162,.32)] sm:right-6">
      <Bot size={23}/>
    </button>
  </>
}
