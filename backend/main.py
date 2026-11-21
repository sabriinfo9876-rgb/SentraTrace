import asyncio
import hashlib
import hmac
import os
import re
import secrets
import time
from contextlib import asynccontextmanager, suppress
from datetime import datetime, timezone
from pathlib import Path
from threading import BoundedSemaphore, Event
from typing import Annotated, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

from .copilot import Language, answer
from .defense import LOGIN_LIMIT, LOGIN_WINDOW, NETWORK_LOGIN_LIMIT, Decision
from .defense import check_ownership, limit_reached, preview_decision
from .email_security import GmailSecurity, GoogleConfig
from .google_login import LoginConfig, google_login_routes
from .store import ROOT, Store, configured_store

COOKIE = "cg_session"
WORKSPACE_HEADER = "X-CyberGuard-Workspace"
HASH_SLOTS = BoundedSemaphore(2)
SESSION_SECONDS = 8 * 60 * 60
EVENT_COLUMNS = "id, type, user_id AS user, resource, risk, reason, status, timestamp, recommendation, source"


class CopilotPrompt(BaseModel):
    message: str = Field(min_length=1, max_length=500)
    language: Language = "en"


class StoreDecision(BaseModel):
    route: Literal["customer-login", "admin-login"]


class SignIn(BaseModel):
    email: str = Field(max_length=254)
    password: str = Field(min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", value):
            raise ValueError("Enter a valid email address.")
        return value


class SignUp(SignIn):
    name: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Enter your name.")
        return value.strip()


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def password_hash(password: str, salt: bytes) -> str:
    if not HASH_SLOTS.acquire(blocking=False):
        raise HTTPException(503, "Sign-in service is busy. Try again in a moment.")
    try:
        return hashlib.scrypt(password.encode(), salt=salt, n=2**17, r=8, p=1,
                              maxmem=160 * 1024 * 1024, dklen=32).hex()
    finally:
        HASH_SLOTS.release()


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def audit(db, user_id: str, message: str):
    db.execute("INSERT INTO audit(user_id, t, msg) VALUES (?, ?, ?)",
               (user_id, timestamp(), message))


def record(db, user_id: str, resource: str, decision: Decision, source: str) -> str:
    event_id = f"EVT-{uuid4().hex[:16]}"
    db.execute("""
        INSERT INTO events(id, user_id, type, resource, risk, reason, status,
                           timestamp, recommendation, source)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (event_id, user_id, decision.type, resource, decision.risk,
          decision.reason, decision.status, timestamp(), decision.recommendation, source))
    if decision.status == "Blocked" or source == "Preview":
        audit(db, user_id, f"{source} · {decision.type} · {decision.status} · {event_id}")
    return event_id


def current_user(request: Request) -> dict:
    token = request.cookies.get(COOKIE, "")
    if 0 < len(token) <= 128:
        with request.app.state.store.connect() as db:
            user = db.execute("""
                SELECT users.id, users.email, users.name FROM sessions
                JOIN users ON sessions.user_id = users.id
                WHERE token_hash = ? AND expires > ?
            """, (digest(token), int(time.time()))).fetchone()
        if user:
            check_workspace(request, user["id"])
            return dict(user)
    raise HTTPException(401, "Sign in to continue.")


def check_workspace(request: Request, user_id: str):
    # The cookie authenticates the caller. This header binds a tab to the account it displayed.
    expected = request.headers.get(WORKSPACE_HEADER)
    if expected is not None and expected != user_id:
        raise HTTPException(401, "Your browser session changed. Sign in to continue.")


User = Annotated[dict, Depends(current_user)]


def start_session(db, request: Request, response: Response, user_id: str, action: str):
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    db.execute("DELETE FROM sessions WHERE expires <= ?", (now,))
    previous = request.cookies.get(COOKIE, "")
    if 0 < len(previous) <= 128:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (digest(previous),))
    db.execute("INSERT INTO sessions VALUES (?, ?, ?)", (digest(token), user_id, now + SESSION_SECONDS))
    audit(db, user_id, action)
    response.set_cookie(COOKIE, token, max_age=SESSION_SECONDS, path="/api",
                        httponly=True, secure=request.app.state.secure_cookie, samesite="strict")


def reserve_attempt(store: Store, scopes: list[tuple[str, int]], seconds: int):
    now = int(time.time())
    with store.connect(write=True) as db:
        db.execute("DELETE FROM rate_limits WHERE expires <= ?", (now,))
        for scope, limit in scopes:
            row = db.execute("SELECT attempts, expires FROM rate_limits WHERE scope = ?", (scope,)).fetchone()
            if row and limit_reached(row["attempts"], limit):
                raise HTTPException(429, "Too many attempts. Try again shortly.",
                                    headers={"Retry-After": str(row["expires"] - now)})
        for scope, _ in scopes:
            db.execute("""
                INSERT INTO rate_limits VALUES (?, 1, ?)
                ON CONFLICT(scope) DO UPDATE SET attempts = attempts + 1
            """, (scope, now + seconds))


def create_app(store: Store | None = None, dist: Path = ROOT / "dist",
               secure_cookie: bool | None = None) -> FastAPI:
    database = store or configured_store()
    mail = GmailSecurity(database, GoogleConfig.from_env())
    google_login = LoginConfig.from_env()

    @asynccontextmanager
    async def lifespan(_app):
        database.initialize()
        stop = Event()
        worker = asyncio.create_task(mail.monitor(stop)) if mail.config else None
        try:
            yield
        finally:
            stop.set()
            if worker:
                worker.cancel()
                with suppress(asyncio.CancelledError):
                    await worker

    app = FastAPI(title="SentraTrace", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store = database
    app.state.secure_cookie = (os.environ.get("CYBERGUARD_SECURE_COOKIE") == "1"
                               if secure_cookie is None else secure_cookie)
    api = APIRouter(prefix="/api")

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, error: RequestValidationError):
        first = error.errors()[0]
        field = first["loc"][-1]
        message = "The request contains invalid values."
        if field in {"email", "password", "name"}:
            message = {
                "email": "Enter a valid email address.",
                "password": "Enter a password of 8–128 characters." if request.url.path.endswith("/signup")
                            else "Enter a password of up to 128 characters.",
                "name": "Enter a name with up to 80 characters.",
            }[field]
        return JSONResponse({"detail": message}, status_code=422)

    @app.middleware("http")
    async def api_headers(request: Request, call_next):
        if request.url.path == "/api" or request.url.path.startswith("/api/"):
            if request.method in {"POST", "PATCH", "PUT", "DELETE"} and (
                request.headers.get("X-CyberGuard-Client") != "1"
                or request.headers.get("Sec-Fetch-Site") in {"cross-site", "same-site"}
            ):
                response = JSONResponse({"detail": "Request origin is not allowed."}, status_code=403)
            else:
                response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            response.headers["X-Content-Type-Options"] = "nosniff"
            return response
        return await call_next(request)

    @api.get("")
    def root():
        return {"service": "SentraTrace"}

    @api.get("/health")
    def health():
        with database.connect() as db:
            db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
        return {"status": "ok", "engine": "rules", "database": "SQLite", "authentication": "Email/password and Google" if google_login else "Local email/password"}

    @api.post("/auth/signup", status_code=201)
    def signup(body: SignUp, request: Request, response: Response):
        peer = request.client.host if request.client else "unknown"
        reserve_attempt(database, [(f"signup:{peer}", 10)], LOGIN_WINDOW)
        salt = secrets.token_bytes(16)
        stored = f"{salt.hex()}:{password_hash(body.password, salt)}"
        user = {"id": uuid4().hex, "email": body.email, "name": body.name}
        with database.connect(write=True) as db:
            inserted = db.execute("""
                INSERT INTO users(id, email, name, password_hash) VALUES (?, ?, ?, ?)
                ON CONFLICT(email) DO NOTHING
            """, (user["id"], user["email"], user["name"], stored))
            if not inserted.rowcount:
                raise HTTPException(409, "An account already exists for this email.")
            start_session(db, request, response, user["id"], "Account created")
        return user

    @api.post("/auth/login")
    def login(body: SignIn, request: Request, response: Response):
        peer = request.client.host if request.client else "unknown"
        reserve_attempt(database, [(f"login:peer:{peer}", NETWORK_LOGIN_LIMIT),
                                   (f"login:identity:{peer}:{digest(body.email)}", LOGIN_LIMIT)], LOGIN_WINDOW)
        with database.connect() as db:
            row = db.execute("SELECT * FROM users WHERE email = ?", (body.email,)).fetchone()
        has_password = row is not None and row["password_hash"] != "!"
        salt, expected = row["password_hash"].split(":") if has_password else ("00" * 16, "0" * 64)
        matched = hmac.compare_digest(password_hash(body.password, bytes.fromhex(salt)), expected)
        if not has_password or not matched:
            raise HTTPException(401, "Email or password is incorrect.")
        with database.connect(write=True) as db:
            start_session(db, request, response, row["id"], "Signed in")
        return {key: row[key] for key in ("id", "email", "name")}

    @api.get("/auth/me")
    def me(user: User):
        return user

    @api.post("/auth/logout", status_code=204)
    def logout(request: Request, response: Response):
        token = request.cookies.get(COOKIE, "")
        if 0 < len(token) <= 128:
            with database.connect(write=True) as db:
                row = db.execute("DELETE FROM sessions WHERE token_hash = ? RETURNING user_id",
                                 (digest(token),)).fetchone()
                if row:
                    check_workspace(request, row["user_id"])
                    audit(db, row["user_id"], "Signed out")
        response.delete_cookie(COOKIE, path="/api", secure=app.state.secure_cookie,
                               httponly=True, samesite="strict")

    @api.get("/workspace")
    def workspace(user: User):
        user_id = user["id"]
        with database.connect() as db:
            counts = db.execute("""
                SELECT count(*) AS total_requests,
                    count(CASE WHEN status = 'Allowed' THEN 1 END) AS safe_requests,
                    count(CASE WHEN status != 'Allowed' THEN 1 END) AS threats_detected,
                    count(CASE WHEN status = 'Blocked' THEN 1 END) AS blocked_attacks
                FROM events WHERE user_id = ?
            """, (user_id,)).fetchone()
            events = db.execute(f"""
                SELECT {EVENT_COLUMNS} FROM events WHERE user_id = ? ORDER BY seq DESC LIMIT 1000
            """, (user_id,)).fetchall()
            notifications = db.execute("""
                SELECT id, '[' || source || '] ' || type || ' · ' || status AS msg,
                       timestamp AS t, notification_read
                FROM events WHERE user_id = ? AND status = 'Blocked' AND notification_dismissed = 0
                UNION ALL
                SELECT 'gmail-' || message_id, '[Gmail] ' || kind, timestamp, notification_read
                FROM gmail_alerts WHERE user_id = ? AND notification_dismissed = 0
                ORDER BY t DESC LIMIT 100
            """, (user_id, user_id)).fetchall()
            trail = db.execute("SELECT t, msg FROM audit WHERE user_id = ? ORDER BY seq DESC LIMIT 100",
                               (user_id,)).fetchall()
        return {
            "stats": dict(counts),
            "events": [dict(row) for row in events],
            "notifs": [{"id": row["id"], "msg": row["msg"], "t": row["t"],
                        "read": bool(row["notification_read"])} for row in notifications],
            "audit": [dict(row) for row in trail],
        }

    @api.post("/notifications/{action}", status_code=204)
    def update_notifications(action: Literal["read", "clear"], user: User):
        column = "notification_read" if action == "read" else "notification_dismissed"
        with database.connect(write=True) as db:
            db.execute(f"UPDATE events SET {column} = 1 WHERE user_id = ? AND status = 'Blocked'",
                       (user["id"],))
            db.execute(f"UPDATE gmail_alerts SET {column} = 1 WHERE user_id = ?", (user["id"],))

    @api.get("/policies")
    def policies(_user: User):
        return [
            "Verify authenticated ownership on account reads",
            f"Limit sign-in to {LOGIN_LIMIT} attempts per email and source per {LOGIN_WINDOW} seconds",
            f"Limit sign-in to {NETWORK_LOGIN_LIMIT} attempts per source per {LOGIN_WINDOW} seconds",
            "Record blocked account access in the workspace audit trail",
        ]

    @api.get("/accounts/{account_id}")
    def account(account_id: str, user: User):
        target = user["id"] if account_id == "me" else account_id
        with database.connect(write=True) as db:
            # Never query or return an account belonging to another identity.
            row = db.execute("SELECT id, email, name FROM users WHERE id = ? AND id = ?",
                             (target, user["id"])).fetchone()
            decision = check_ownership(user["id"], row["id"] if row else None)
            record(db, user["id"], "/api/accounts/{account_id}", decision, "Live")
        if row is None:
            raise HTTPException(404, "Account unavailable.")
        return dict(row)

    @api.post("/simulate/{kind}")
    def preview(kind: Literal["bola", "brute-force"], user: User):
        resource, decision = preview_decision(kind)
        with database.connect(write=True) as db:
            event_id = record(db, user["id"], resource, decision, "Preview")
        return {
            "attack": decision.type, "risk_score": decision.risk,
            "explanation": decision.reason, "defender_action": decision.status,
            "remediation": decision.recommendation,
            "raw": {"id": event_id, "source": "Preview", "resource": resource},
        }

    @api.post("/copilot")
    def copilot(body: CopilotPrompt, user: User):
        if not body.message.strip():
            raise HTTPException(422, "Enter a question.")
        reserve_attempt(database, [(f"copilot:{user['id']}", 15)], 60)
        text, mode = answer(database, user["id"], body.message.strip(), body.language)
        return {"text": text, "mode": mode}

    @api.get("/integrations/ma-hijab")
    def integration(user: User):
        with database.connect() as db:
            row = db.execute("SELECT created_at FROM store_connection WHERE user_id = ?", (user["id"],)).fetchone()
        return {"configured": row is not None}

    @api.post("/integrations/ma-hijab/key", status_code=201)
    def store_key(user: User):
        token = secrets.token_urlsafe(32)
        with database.connect(write=True) as db:
            db.execute("""
                INSERT INTO store_connection VALUES (?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET token_hash = excluded.token_hash, created_at = excluded.created_at
            """, (user["id"], digest(token), timestamp()))
        return {"key": token}

    def verify_store_key(request: Request):
        authorization = request.headers.get("authorization", "")
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != "bearer" or not 0 < len(token) <= 128:
            raise HTTPException(401, "Store integration key required.")
        key_hash = digest(token)
        with database.connect() as db:
            key = db.execute("SELECT user_id FROM store_connection WHERE token_hash = ?", (key_hash,)).fetchone()
        if key is None:
            raise HTTPException(401, "Store integration key is invalid.")
        return key_hash, key["user_id"]

    @api.get("/integrations/ma-hijab/check")
    def check_store_key(request: Request):
        verify_store_key(request)
        return {"status": "connected"}

    @api.post("/integrations/ma-hijab/events", status_code=201)
    def store_event(body: StoreDecision, request: Request):
        key_hash, user_id = verify_store_key(request)
        reserve_attempt(database, [(f"store-events:{user_id}", 60)], 60)
        resources = {"customer-login": "/api/auth/login", "admin-login": "/api/admin/login"}
        decision = Decision("M.A-HIJAB rate limit", "Blocked", 70,
                            "M.A-HIJAB reported that its server rejected a request after the rate limit was reached.",
                            "Review the store's rate-limit settings and recent login activity.")
        with database.connect(write=True) as db:
            current = db.execute("SELECT user_id FROM store_connection WHERE token_hash = ?", (key_hash,)).fetchone()
            if current is None:
                raise HTTPException(401, "Store integration key is invalid.")
            event_id = record(db, current["user_id"], "M.A-HIJAB " + resources[body.route], decision, "Live")
        return {"id": event_id}

    api.include_router(mail.routes(current_user, COOKIE))
    api.include_router(google_login_routes(database, google_login, current_user, COOKIE, start_session, reserve_attempt))
    app.include_router(api)

    if (dist / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{path:path}", include_in_schema=False)
        def frontend(path: str):
            if path == "api" or path.startswith("api/"):
                raise HTTPException(404, "API route not found.")
            if path in {"icon.svg", "sw.js"} and (dist / path).is_file():
                return FileResponse(dist / path)
            return FileResponse(dist / "index.html", headers={"Cache-Control": "no-cache"})

    return app


app = create_app()
