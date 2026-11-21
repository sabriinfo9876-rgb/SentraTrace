# SentraTrace — API Security Monitoring

React dashboard connected to a FastAPI backend. Accounts, sessions, events, notifications and audit entries are stored in SQLite. Each signup creates a private workspace.

## Run on Windows

Extract the ZIP and open PowerShell in the `cyberguard-main` folder. Use Python 3.12 or 3.13.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) and choose **Create an account**. The ZIP includes the built frontend, so this setup uses one server and needs no Node.js install. Use the same hostname each time so the browser sends the same session cookie. The app creates `var/cyberguard.sqlite3` on first startup. Keep that directory if you want to preserve your accounts and history.

Browser-local demo accounts from earlier releases need to sign up once on the new backend.

## Verify the connection

1. Open **Agents** and confirm the connection is **Connected**, the database is **SQLite**, and authentication shows the enabled sign-in methods.
2. Open **API playground**, select **GET /api/accounts/me**, and send the request. The response shows your own account and records a Live event.
3. Open **Simulation lab** and run either policy preview. The backend evaluates fixed inputs with its defense rules and saves a Preview event. Find it in **Incidents**, **Notifications**, and **Audit log**.
4. Sign out and sign in again. Your workspace should still contain its event history.

The dashboard counters include Live and Preview decisions. Live coverage is limited to this app's account endpoint. The frontend shows the latest 1,000 events and latest 100 audit entries and notifications. Sign-in limits are enforced on the backend before password verification.

## Frontend development

Leave FastAPI running on port 8000. In a second terminal, use Node.js 22.12+ or 24 and run:

```powershell
npm ci
npm run dev
```

Open [http://localhost:5173](http://localhost:5173). Vite forwards same-origin `/api` requests to FastAPI. To rebuild the version served by FastAPI, run `npm run build` and restart FastAPI.

## Backend regression tests

```powershell
.\.venv\Scripts\python.exe -m pip install httpx==0.28.1
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests use temporary databases and cover signup, login, rejected and expired sessions, ownership, workspace isolation, rate-limit handling, and persistence.

## Configuration

- `CYBERGUARD_DB` sets the SQLite path. Use an absolute path on a persistent disk when running outside the extracted folder.
- `CYBERGUARD_SECURE_COOKIE=1` enables HTTPS-only session cookies. Set it when serving the app behind HTTPS.
- Email/password authentication is available by default. Enable Google sign-in using the setup below. The defense engine and workspace co-pilot use rules. Supabase, 2FA, and external model providers require separate integration.

## Connect Gmail and review Google security alerts

SentraTrace can display supported Google security notices received in a connected Gmail inbox. Google still decides which activity is suspicious and which notices it emails. An address without Google authorization supplies no activity data. The inbox can also receive notices for accounts that list it as a recovery address. A general notice should be reviewed in Google Account before concluding that someone gained access.

1. In Google Cloud, enable **Gmail API**. Configure the OAuth consent screen, add your address as a test user for local development, and create a **Web application** OAuth client.
2. Add this exact authorized redirect URI for the local setup: `http://127.0.0.1:8000/api/email-security/callback`. Open SentraTrace using the same hostname and port.
3. Set the following values in the PowerShell window before starting the server. Keep the secret and token key private. Reuse the same token key across restarts.

```powershell
$env:CYBERGUARD_GOOGLE_CLIENT_ID = '<Google OAuth client ID>'
$env:CYBERGUARD_GOOGLE_CLIENT_SECRET = '<Google OAuth client secret>'
$env:CYBERGUARD_GOOGLE_REDIRECT_URI = 'http://127.0.0.1:8000/api/email-security/callback'
$env:CYBERGUARD_GOOGLE_TOKEN_KEY = '<persistent Fernet key>'
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

Generate the Fernet key once with `.\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`. Use your existing venv to reinstall the requirements after updating SentraTrace. The no-access-log setting keeps OAuth callback query strings out of local HTTP access logs.

4. Sign in to SentraTrace, open **Email security**, click **Connect Gmail**, and grant access on Google's consent page.
5. The running FastAPI process checks the connection about every five minutes. Matching notices appear under **Email security** and **Notifications**. There is also a **Check for alerts** button subject to the same interval.

The Gmail API grant is read-only. SentraTrace requests selected message headers, checks the Google sender and Gmail's authentication result, and recognizes supported English security subjects. It checks up to three pages of matching message IDs within the most recent seven days. It stores the alert type, message ID and received time, plus an encrypted connection token. Disconnect removes the local connection and alert records. You can remove the app's Google access from your Google Account's third-party connections page.

For a public product, follow Google's Gmail restricted-scope verification requirements. Use HTTPS and keep OAuth callback query strings out of any reverse-proxy access logs. Until valid Google OAuth settings are configured, the feature shows its unavailable state.

## Enable Continue with Google

Google sign-in requests only basic identity scopes. Gmail security monitoring has its own consent and configuration. You may use the same Google Cloud Web application OAuth client for both features and register both callback URLs.

1. Add `http://127.0.0.1:8000/api/auth/google/callback` to **Authorized redirect URIs** for the OAuth client. Add your account as a test user if the Google app is in testing.
2. After updating and reinstalling `backend/requirements.txt`, set the Google client ID and secret described above, and set this additional value in the PowerShell window:

```powershell
$env:CYBERGUARD_GOOGLE_LOGIN_REDIRECT_URI = 'http://127.0.0.1:8000/api/auth/google/callback'
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --no-access-log
```

3. Open `http://127.0.0.1:8000`. New users can choose **Continue with Google** to create a workspace. Existing users should first sign in with their password, then choose **Settings → Link Google account** to keep their current workspace. A matching email address alone does not merge accounts.

Both callbacks must be registered separately when using both features. Google sign-in works without the Gmail API, Gmail callback, or Gmail token encryption key. A Google-created SentraTrace account signs in through Google.

## Security co-pilot

The co-pilot processes questions through the signed-in workspace API. Incident summaries read the account's SQLite records and show Live and Preview counts. Help topics include authorization, login limits, reports, connected Gmail notices and store telemetry. Replies are available in English, Roman Urdu and Urdu.

Use the built-in answers without an API key. To enable Gemini rephrasing for supported help topics, set these PowerShell variables before starting FastAPI:

```powershell
$env:CYBERGUARD_GEMINI_API_KEY = '<server API key>'
$env:CYBERGUARD_GEMINI_MODEL = 'gemini-3.5-flash-lite'
```

Gemini receives the language and approved help text. Incident data and message text stay in SentraTrace. If the provider is unavailable, the co-pilot returns built-in help and labels it.

## M.A-HIJAB store integration

Existing integration settings keep the `CYBERGUARD_` prefix.

**Settings → M.A-HIJAB connection** creates a private key for the store's Express server. Configure the store with `CYBERGUARD_URL=http://127.0.0.1:8000` and `CYBERGUARD_STORE_KEY=<private key>`. For a hosted integration, use the deployed HTTPS SentraTrace origin. Record delivery is best effort. A reported store login rate-limit decision appears in **Incidents** as **Live**. Store order data and the frontend demo stay outside this integration.

### Verify the local store integration key

In the M.A-HIJAB PowerShell folder, run the command below. Node reads the values from
the store's `.env`. It prints the check result without displaying the key or recording an incident.
This command is for the local setup at port 8000.

```powershell
node --env-file=.env -e "const key=(process.env.CYBERGUARD_STORE_KEY||'').trim(); const url=(process.env.CYBERGUARD_URL||'').trim().replace(/\/$/,''); if(!key||key==='PASTE_YOUR_KEY_HERE'||!['http://127.0.0.1:8000','http://localhost:8000'].includes(url)){console.error('Check CYBERGUARD_URL and CYBERGUARD_STORE_KEY in .env');process.exit(1)} fetch(url+'/api/integrations/ma-hijab/check',{headers:{Authorization:'Bearer '+key},redirect:'error',signal:AbortSignal.timeout(5000)}).then(r=>console.log(r.ok?'Connected - integration key accepted':'HTTP '+r.status)).catch(()=>console.error('SentraTrace could not be reached'))"
```

## Deploy to Railway

1. Push this project's files from inside `cyberguard-main` to a dedicated SentraTrace GitHub repository. The `Dockerfile`, `railway.toml`, and `package.json` should sit at the repo root. Keep private environment files and local databases out of Git. Railway builds the frontend from source and starts FastAPI on its assigned port.
2. In Railway, create a project with **Deploy from GitHub repo** and select the SentraTrace repository. Keep one service replica for the SQLite deployment.
3. Attach a Railway Volume to this service with mount path `/data`. In the service's **Variables**, set `CYBERGUARD_DB=/data/sentratrace.sqlite3`. With this setup, redeployments use the same database. The hosted database starts fresh.
4. Once the service is running, open **Settings → Networking → Public Networking → Generate Domain**. Check `https://YOUR-DOMAIN/api/health`, then open the domain root and create a fresh demo account. Submit the domain root to your teacher.
5. For a hosted M.A-HIJAB backend, set its `CYBERGUARD_URL` to the Railway HTTPS origin, and set `CYBERGUARD_STORE_KEY` to a key created in the hosted SentraTrace workspace. For Google sign-in or Gmail monitoring, configure the HTTPS callback URLs for that same Railway domain.

Optional credentials belong in Railway Variables. The dashboard and local email/password login work without Google or Gemini configuration.
