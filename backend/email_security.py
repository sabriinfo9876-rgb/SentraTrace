import asyncio
import base64
import hashlib
import logging
import os
import re
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parseaddr
from threading import Event
from typing import Annotated
from urllib.parse import quote, urlencode, urlsplit

import httpx
from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .store import Store

LOGGER = logging.getLogger(__name__)
GOOGLE_AUTH = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN = "https://oauth2.googleapis.com/token"
GMAIL = "https://gmail.googleapis.com/gmail/v1/users/me"
SCOPE = "https://www.googleapis.com/auth/gmail.readonly"
SENDER = "no-reply@accounts.google.com"
CALLBACK = "/api/email-security/callback"
STATE_COOKIE = "cg_gmail_state"
INTERVAL = 300


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def alert_kind(headers: list[dict]) -> str | None:
    values: dict[str, str] = {}
    for header in headers:
        values.setdefault(header["name"].lower(), header["value"].strip())
    if parseaddr(values.get("from", ""))[1].lower() != SENDER:
        return None
    authentication = values.get("authentication-results", "").lower()
    if not re.match(r"^mx\.google\.com\s*;", authentication):
        return None
    if not re.search(r"(?:^|;)\s*dmarc=pass\b[^;]*\bheader\.from=accounts\.google\.com(?:\s|;|$)", authentication):
        return None
    subject = values.get("subject", "").casefold().replace("’", "'")
    if re.search(r"\b(suspicious sign[ -]?in prevented|sign[ -]?in attempt blocked|blocked sign[ -]?in attempt)\b", subject):
        return "Blocked sign-in reported"
    if re.search(r"\b(security alert|suspicious sign[ -]?in|unusual sign[ -]?in|new sign[ -]?in)\b", subject):
        return "Google security activity to review"
    return None


@dataclass(frozen=True)
class GoogleConfig:
    client_id: str
    secret: str
    redirect: str
    cipher: Fernet

    @classmethod
    def from_env(cls):
        names = ("CLIENT_ID", "CLIENT_SECRET", "REDIRECT_URI", "TOKEN_KEY")
        user_config = [os.getenv(f"CYBERGUARD_GOOGLE_{name}", "").strip() for name in names]
        if not all(user_config):
            return None
        client_id, secret, redirect, key = user_config
        try:
            uri = urlsplit(redirect)
            if (uri.path != CALLBACK or uri.query or uri.fragment or uri.username or not uri.hostname
                    or (uri.scheme != "https" and not (
                        uri.scheme == "http" and uri.hostname in {"localhost", "127.0.0.1"}
                    ))):
                raise ValueError("Invalid callback.")
            return cls(client_id, secret, redirect, Fernet(key.encode("ascii")))
        except ValueError:
            LOGGER.error("Invalid Gmail OAuth callback URI or token encryption key.")
            return None


class MailboxError(Exception):
    pass


class GmailSecurity:
    def __init__(self, store: Store, config: GoogleConfig | None):
        self.store = store
        self.config = config

    def request(self, method: str, url: str, **kwargs):
        try:
            with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
                response = client.request(method, url, **kwargs)
                if not response.is_success:
                    if url == GOOGLE_TOKEN and response.status_code == 400 and response.json().get("error") == "invalid_grant":
                        raise MailboxError("Google access expired or was revoked. Reconnect Gmail.")
                    raise MailboxError("Google did not complete this request. Check access and try again.")
                return response.json()
        except (httpx.HTTPError, ValueError):
            raise MailboxError("Google could not be reached. Try again shortly.") from None

    def token(self, **grant):
        return self.request("POST", GOOGLE_TOKEN, data={
            "client_id": self.config.client_id, "client_secret": self.config.secret, **grant
        })

    def fetch_alerts(self, access: str, stop: Event | None = None):
        headers = {"Authorization": f"Bearer {access}"}
        params = {"q": f"from:{SENDER} newer_than:7d", "maxResults": 50,
                  "fields": "messages(id),nextPageToken"}
        for _ in range(3):
            if stop and stop.is_set():
                return
            listing = self.request("GET", f"{GMAIL}/messages", headers=headers, params=params)
            for entry in listing.get("messages", []):
                if stop and stop.is_set():
                    return
                message_id = entry["id"]
                message = self.request("GET", f"{GMAIL}/messages/{quote(message_id, safe='')}", headers=headers,
                                       params=[("format", "metadata"), ("metadataHeaders", "From"),
                                               ("metadataHeaders", "Subject"), ("metadataHeaders", "Authentication-Results"),
                                               ("fields", "internalDate,payload(headers)")])
                kind = alert_kind(message.get("payload", {}).get("headers", []))
                if kind and message.get("internalDate"):
                    received = datetime.fromtimestamp(int(message["internalDate"]) / 1000, timezone.utc).isoformat()
                    yield message_id, kind, received
            if not listing.get("nextPageToken"):
                return
            params["pageToken"] = listing["nextPageToken"]

    def check(self, user_id: str, stop: Event | None = None):
        now = int(time.time())
        with self.store.connect(write=True) as db:
            connection = db.execute("""
                UPDATE gmail_connections SET next_check = ?
                WHERE user_id = ? AND next_check <= ?
                RETURNING generation, refresh_token
            """, (now + INTERVAL, user_id, now)).fetchone()
        if not connection:
            return
        generation = connection["generation"]
        try:
            refresh_token = self.config.cipher.decrypt(connection["refresh_token"]).decode()
            token = self.token(refresh_token=refresh_token, grant_type="refresh_token")
            for message_id, kind, received in self.fetch_alerts(token["access_token"], stop):
                with self.store.connect(write=True) as db:
                    db.execute("""
                        INSERT OR IGNORE INTO gmail_alerts(user_id, message_id, kind, timestamp)
                        SELECT user_id, ?, ?, ? FROM gmail_connections WHERE user_id = ? AND generation = ?
                    """, (message_id, kind, received, user_id, generation))
            if stop and stop.is_set():
                return
            with self.store.connect(write=True) as db:
                db.execute("UPDATE gmail_connections SET last_checked = ?, failure = NULL WHERE user_id = ? AND generation = ?",
                           (datetime.now(timezone.utc).isoformat(), user_id, generation))
        except (MailboxError, InvalidToken, KeyError, TypeError, ValueError) as failure:
            message = str(failure) if isinstance(failure, MailboxError) else "Gmail connection could not be read. Reconnect Gmail."
            with self.store.connect(write=True) as db:
                db.execute("UPDATE gmail_connections SET failure = ? WHERE user_id = ? AND generation = ?",
                           (message, user_id, generation))

    def check_due(self, stop: Event):
        with self.store.connect() as db:
            due = db.execute("SELECT user_id FROM gmail_connections WHERE next_check <= ?",
                             (int(time.time()),)).fetchall()
        for connection in due:
            if stop.is_set():
                return
            self.check(connection["user_id"], stop)

    async def monitor(self, stop: Event):
        while not stop.is_set():
            try:
                await asyncio.to_thread(self.check_due, stop)
            except Exception:
                LOGGER.exception("Gmail security alert scan failed.")
            await asyncio.sleep(15)

    def routes(self, current_user, session_cookie: str):
        api = APIRouter(prefix="/email-security")
        User = Annotated[dict, Depends(current_user)]

        @api.get("")
        def status(user: User):
            with self.store.connect() as db:
                connection = db.execute("""
                    SELECT email, last_checked, failure, next_check FROM gmail_connections WHERE user_id = ?
                """, (user["id"],)).fetchone()
                alerts = db.execute("""
                    SELECT message_id AS id, kind, timestamp FROM gmail_alerts WHERE user_id = ?
                    ORDER BY timestamp DESC LIMIT 100
                """, (user["id"],)).fetchall()
            return {"configured": self.config is not None, "connection": dict(connection) if connection else None,
                    "alerts": [dict(message) for message in alerts]}

        @api.post("/connect")
        def connect(user: User, request: Request, response: Response):
            if not self.config:
                raise HTTPException(503, "Gmail connection is not configured.")
            origin = request.headers.get("origin")
            if origin and origin != self.config.redirect.removesuffix(CALLBACK):
                raise HTTPException(409, "Open SentraTrace at the same address configured for the Gmail callback.")
            state = secrets.token_urlsafe(32)
            verifier = secrets.token_urlsafe(48)
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
            with self.store.connect(write=True) as db:
                db.execute("DELETE FROM gmail_oauth WHERE expires <= ? OR user_id = ?", (int(time.time()), user["id"]))
                db.execute("INSERT INTO gmail_oauth VALUES (?, ?, ?, ?, ?)",
                           (digest(state), user["id"], digest(request.cookies[session_cookie]), verifier, int(time.time()) + 600))
            response.set_cookie(STATE_COOKIE, state, max_age=600, path=CALLBACK,
                                httponly=True, secure=self.config.redirect.startswith("https:"), samesite="lax")
            response.headers["Referrer-Policy"] = "no-referrer"
            return {"url": GOOGLE_AUTH + "?" + urlencode({
                "client_id": self.config.client_id, "redirect_uri": self.config.redirect,
                "response_type": "code", "scope": SCOPE, "access_type": "offline",
                "prompt": "consent select_account", "state": state,
                "code_challenge": challenge, "code_challenge_method": "S256"
            })}

        @api.get("/callback")
        def callback(request: Request, code: str = "", state: str = ""):
            result = RedirectResponse("/email-security?oauth=failed", status_code=303,
                                      headers={"Referrer-Policy": "no-referrer"})
            result.delete_cookie(STATE_COOKIE, path=CALLBACK, httponly=True, samesite="lax",
                                 secure=bool(self.config and self.config.redirect.startswith("https:")))
            if not self.config or not 0 < len(state) <= 128 or state != request.cookies.get(STATE_COOKIE):
                return result
            with self.store.connect(write=True) as db:
                pending = db.execute("""
                    DELETE FROM gmail_oauth WHERE state_hash = ? AND expires > ? AND EXISTS (
                        SELECT 1 FROM sessions WHERE token_hash = gmail_oauth.session_hash
                        AND user_id = gmail_oauth.user_id AND expires > ?
                    ) RETURNING user_id, session_hash, verifier
                """, (digest(state), int(time.time()), int(time.time()))).fetchone()
            if not pending or not code or len(code) > 2048:
                return result
            try:
                tokens = self.token(code=code, code_verifier=pending["verifier"],
                                    redirect_uri=self.config.redirect, grant_type="authorization_code")
                if SCOPE not in tokens.get("scope", "").split() or not tokens.get("refresh_token"):
                    return result
                profile = self.request("GET", f"{GMAIL}/profile",
                                       headers={"Authorization": f"Bearer {tokens['access_token']}"},
                                       params={"fields": "emailAddress"})
                email = profile["emailAddress"].strip().lower()
                if not email:
                    return result
            except (MailboxError, KeyError, TypeError):
                return result
            encrypted = self.config.cipher.encrypt(tokens["refresh_token"].encode())
            with self.store.connect(write=True) as db:
                active = db.execute("SELECT 1 FROM sessions WHERE token_hash = ? AND user_id = ? AND expires > ?",
                                    (pending["session_hash"], pending["user_id"], int(time.time()))).fetchone()
                if not active:
                    return result
                db.execute("""
                    DELETE FROM gmail_alerts WHERE user_id = ? AND NOT EXISTS (
                        SELECT 1 FROM gmail_connections WHERE user_id = ? AND email = ?
                    )
                """, (pending["user_id"], pending["user_id"], email))
                db.execute("""
                    INSERT INTO gmail_connections(user_id, generation, email, refresh_token) VALUES (?, ?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET generation = excluded.generation, email = excluded.email,
                    refresh_token = excluded.refresh_token, next_check = 0, last_checked = NULL, failure = NULL
                """, (pending["user_id"], secrets.token_hex(16), email, encrypted))
            result.headers["location"] = "/email-security?oauth=connected"
            return result

        @api.post("/check")
        def check(user: User, tasks: BackgroundTasks):
            if not self.config:
                raise HTTPException(503, "Gmail connection is not configured.")
            with self.store.connect() as db:
                if not db.execute("SELECT 1 FROM gmail_connections WHERE user_id = ?", (user["id"],)).fetchone():
                    raise HTTPException(409, "Connect Gmail before checking for alerts.")
            tasks.add_task(self.check, user["id"])
            return status(user)

        @api.post("/disconnect")
        def disconnect(user: User):
            with self.store.connect(write=True) as db:
                for table in ("gmail_oauth", "gmail_connections", "gmail_alerts"):
                    db.execute(f"DELETE FROM {table} WHERE user_id = ?", (user["id"],))
            return Response(status_code=204)

        return api
