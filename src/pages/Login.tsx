import { FormEvent, useEffect, useState } from 'react'
import { Link, Navigate, useLocation } from 'react-router-dom'
import { Eye, EyeOff, ShieldCheck } from 'lucide-react'
import ThemeToggle from '../components/ThemeToggle'
import { useApp } from '../context/AppContext'

import { errorMessage, getGoogleLogin, signIn, signUp, startGoogleLogin } from '../services/api'

const field = 'w-full rounded-md px-4 py-3.5 pr-12 text-sm transition'

export default function Login() {
  const { authed, login, checkingSession, sessionError } = useApp()
  const location = useLocation()
  const isSignup = location.pathname === '/signup'
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [err, setErr] = useState('')
  const [busy, setBusy] = useState(false)
  const [googleBusy, setGoogleBusy] = useState(false)
  const [googleAvailable, setGoogleAvailable] = useState(false)
  const googleResult = new URLSearchParams(location.search).get('google')
  const googleError = googleResult === 'link-first'
    ? 'Sign in with your existing password, then link Google in Settings.'
    : googleResult === 'failed' ? 'Google sign-in did not finish. Try again.' : ''
  useEffect(() => {
    const controller = new AbortController()
    getGoogleLogin(controller.signal).then(result => {
      if (!controller.signal.aborted) setGoogleAvailable(result.configured)
    }).catch(() => {})
    return () => controller.abort()
  }, [])
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  if (checkingSession) return <div role="status" className="p-8 text-muted">Checking session…</div>
  if (authed) return <Navigate to="/" replace />

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    if (busy || googleBusy) return
    setErr('')
    if (isSignup && password !== confirmPassword) {
      setErr('The passwords do not match.')
      return
    }

    setBusy(true)
    try {
      const account = isSignup
        ? await signUp(name.trim(), email.trim(), password)
        : await signIn(email.trim(), password)
      login(account)
    } catch (error) {
      setErr(errorMessage(error))
    } finally {
      setBusy(false)
    }
  }

  const continueWithGoogle = async () => {
    setGoogleBusy(true)
    setErr('')
    try {
      window.location.assign(await startGoogleLogin())
    } catch (error) {
      setErr(errorMessage(error))
      setGoogleBusy(false)
    }
  }

  return (
    <div className="min-h-screen md:grid md:grid-cols-[1.08fr_.92fr]">
      <section className="hidden md:flex relative isolate flex-col overflow-hidden border-b border-[var(--border-subtle)] bg-[var(--bg-nav)] px-7 py-7 sm:px-10 md:min-h-screen md:border-b-0 md:border-r md:px-12 md:py-10">
        <div aria-hidden="true" className="pointer-events-none absolute inset-0 -z-10 overflow-hidden">
          <div className="absolute inset-0 opacity-30 [background-image:linear-gradient(rgba(214,92,235,.08)_1px,transparent_1px),linear-gradient(90deg,rgba(214,92,235,.08)_1px,transparent_1px)] [background-size:54px_54px] [mask-image:radial-gradient(ellipse_at_55%_48%,black,transparent_75%)]" />
          <div className="absolute left-[28%] top-[25%] h-72 w-72 rounded-full bg-[#8A32A2]/20 blur-[100px]" />
          <div className="absolute bottom-[-18%] right-[-10%] h-72 w-72 rounded-full bg-[#D65CEB]/10 blur-[100px]" />
        </div>

        <Link to="/" className="relative z-10 inline-flex w-fit items-center gap-2.5 text-lg font-semibold tracking-tight text-ink" aria-label="SentraTrace home">
          <ShieldCheck aria-hidden="true" size={27} strokeWidth={1.8} className="text-accent" />
          <span>Sentra<span className="text-accent">Trace</span></span>
        </Link>

        <div className="relative flex flex-1 items-center justify-center py-6 lg:py-0">
          <div aria-hidden="true" className="absolute h-64 w-64 rounded-full bg-[#A644D6]/20 blur-[75px] sm:h-80 sm:w-80" />
          <div className="relative h-[260px] w-[260px] sm:h-[340px] sm:w-[340px]">
            <svg aria-hidden="true" viewBox="0 0 340 360" className="h-full w-full overflow-visible">
              <defs>
                <linearGradient id="signupShieldFill" x1="48" y1="26" x2="292" y2="326" gradientUnits="userSpaceOnUse">
                  <stop stopColor="#F4E9FF" stopOpacity=".23" />
                  <stop offset=".45" stopColor="#A987D4" stopOpacity=".10" />
                  <stop offset="1" stopColor="#D65CEB" stopOpacity=".02" />
                </linearGradient>
                <linearGradient id="signupShieldStroke" x1="64" y1="40" x2="286" y2="328" gradientUnits="userSpaceOnUse">
                  <stop stopColor="var(--neon)" />
                  <stop offset=".38" stopColor="var(--neon)" />
                  <stop offset="1" stopColor="#A644D6" />
                </linearGradient>
                <filter id="signupShieldGlow" x="-35%" y="-25%" width="170%" height="170%">
                  <feGaussianBlur stdDeviation="9" result="blur" />
                  <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
              </defs>
              <path d="M170 20 286 66v90c0 91-50 143-116 183C104 299 54 247 54 156V66z" fill="url(#signupShieldFill)" stroke="#C77BEB" strokeOpacity=".35" strokeWidth="18" filter="url(#signupShieldGlow)" />
              <path d="M170 20 286 66v90c0 91-50 143-116 183C104 299 54 247 54 156V66z" fill="url(#signupShieldFill)" stroke="url(#signupShieldStroke)" strokeWidth="3" />
              <path d="M170 42 264 79v77c0 72-36 116-94 153-58-37-94-81-94-153V79z" fill="none" stroke="var(--neon)" strokeOpacity=".34" strokeWidth="1.5" />
              <path d="m125 178 31 31 62-70" fill="none" stroke="var(--neon)" strokeLinecap="round" strokeLinejoin="round" strokeWidth="8" opacity=".8" />
              <path d="M65 70 170 29l105 41" fill="none" stroke="var(--neon)" strokeLinecap="round" strokeWidth="2" opacity=".72" />
            </svg>

          </div>
        </div>

        <div className="relative z-10 pb-2">
          <p className="mb-3 font-mono text-[10px] uppercase tracking-[.24em] text-accent">API security monitoring</p>
          <h1 className="max-w-xl text-3xl font-semibold leading-tight tracking-tight text-ink sm:text-4xl">Unauthorized requests stop here.</h1>
          <p className="mt-3 max-w-lg text-sm leading-6 text-muted">Review account access decisions and security alerts in one workspace.</p>
        </div>
      </section>

      <section className="relative flex min-h-dvh items-center justify-center bg-[var(--bg-primary)] px-7 py-20 sm:px-12 md:px-10 lg:px-16">
        <Link to="/" className="absolute left-5 top-5 inline-flex items-center gap-2 text-sm font-semibold md:hidden" aria-label="SentraTrace home">
          <ShieldCheck aria-hidden="true" size={20} className="text-accent"/> SentraTrace
        </Link>
        <div className="absolute right-5 top-5 sm:right-8 sm:top-8"><ThemeToggle /></div>
        <form onSubmit={submit} className="w-full max-w-[390px] space-y-5">
          <div className="mb-8">
            <p className="mb-2 font-mono text-[10px] uppercase tracking-[.22em] text-accent">{isSignup ? 'Get protected' : 'Secure access'}</p>
            <h2 className="text-4xl font-semibold tracking-tight text-ink">{isSignup ? 'Create account' : 'Sign in'}</h2>
            <p className="mt-2 text-sm text-muted">{isSignup ? 'Start securing your APIs with SentraTrace.' : 'Welcome back. Sign in to your workspace.'}</p>
          </div>

          {isSignup && (
            <label className="block text-sm font-medium text-ink">
              Name
              <input required maxLength={80} autoComplete="name" className={`${field} mt-2`} placeholder="Your name" value={name} onChange={event => setName(event.target.value)} />
            </label>
          )}
          <label className="block text-sm font-medium text-ink">
            Email
            <input required maxLength={254} type="email" autoComplete="email" className={`${field} mt-2`} placeholder="you@example.com" value={email} onChange={event => setEmail(event.target.value)} />
          </label>
          <label className="block text-sm font-medium text-ink">
            Password
            <span className="relative mt-2 block">
              <input required maxLength={128} minLength={isSignup ? 8 : 1} type={showPassword ? 'text' : 'password'} autoComplete={isSignup ? 'new-password' : 'current-password'} className={field} placeholder={isSignup ? 'At least 8 characters' : 'Enter your password'} value={password} onChange={event => setPassword(event.target.value)} />
              <button type="button" onClick={() => setShowPassword(value => !value)} aria-label={showPassword ? 'Hide password' : 'Show password'} className="absolute inset-y-0 right-3 flex items-center text-muted transition hover:text-ink">
                {showPassword ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </span>
          </label>
          {isSignup && (
            <label className="block text-sm font-medium text-ink">
              Confirm password
              <span className="relative mt-2 block">
                <input required maxLength={128} type={showConfirmPassword ? 'text' : 'password'} autoComplete="new-password" className={field} placeholder="Re-enter your password" value={confirmPassword} onChange={event => setConfirmPassword(event.target.value)} />
                <button type="button" onClick={() => setShowConfirmPassword(value => !value)} aria-label={showConfirmPassword ? 'Hide confirm password' : 'Show confirm password'} className="absolute inset-y-0 right-3 flex items-center text-muted transition hover:text-ink">
                  {showConfirmPassword ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </span>
            </label>
          )}

          {(err || sessionError || googleError) && <p role="alert" className="rounded-md border border-red-400/20 bg-red-400/10 px-3 py-2 text-sm text-bad">{err || sessionError || googleError}</p>}
          <button disabled={busy || googleBusy} className="w-full rounded-md bg-accent px-4 py-3.5 font-semibold disabled:cursor-wait disabled:opacity-60">
            {busy ? (isSignup ? 'Creating account…' : 'Signing in…') : isSignup ? 'Create account' : 'Sign in'}
          </button>

          {googleAvailable && <button type="button" disabled={busy || googleBusy} onClick={continueWithGoogle} className="w-full rounded-md border border-accent/40 px-4 py-3.5 font-semibold text-ink disabled:opacity-60">
            {googleBusy ? 'Opening Google…' : 'Continue with Google'}
          </button>}

          <p className="text-center text-sm text-muted">
            {isSignup ? 'Already have an account? ' : 'New to SentraTrace? '}
            <Link to={isSignup ? '/login' : '/signup'} className="font-semibold text-accent hover:text-ink hover:underline">
              {isSignup ? 'Sign in' : 'Create an account'}
            </Link>
          </p>
        </form>
      </section>
    </div>
  )
}
