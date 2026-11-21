import base64
import hashlib
import os
import re
import secrets
import time
from dataclasses import dataclass
from typing import Annotated
from urllib.parse import urlencode, urlsplit
from uuid import uuid4

import httpx
import jwt
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import RedirectResponse

from .email_security import GOOGLE_AUTH, GOOGLE_TOKEN, digest
from .store import Store

CALLBACK = "/api/auth/google/callback"
COOKIE = "cg_google_login"
JWKS = "https://www.googleapis.com/oauth2/v3/certs"
ISSUERS = ("https://accounts.google.com", "accounts.google.com")


@dataclass(frozen=True)
class LoginConfig:
    client_id: str
    secret: str
    redirect: str

    @classmethod
    def from_env(cls):
        client_id = os.getenv("CYBERGUARD_GOOGLE_CLIENT_ID", "").strip()
        secret = os.getenv("CYBERGUARD_GOOGLE_CLIENT_SECRET", "").strip()
        redirect = os.getenv("CYBERGUARD_GOOGLE_LOGIN_REDIRECT_URI", "").strip()
        if not all((client_id, secret, redirect)):
            return None
        try:
            uri = urlsplit(redirect)
            if (uri.path == CALLBACK and not (uri.query or uri.fragment or uri.username)
                    and uri.hostname and (uri.scheme == "https" or (
                        uri.scheme == "http" and uri.hostname in {"127.0.0.1", "localhost"}))):
                return cls(client_id, secret, redirect)
        except ValueError:
            pass
        return None

    @property
    def secure(self):
        return self.redirect.startswith("https:")


def verify_id_token(id_token: str, keys: dict, client_id: str, nonce: str) -> dict:
    header = jwt.get_unverified_header(id_token)
    if header.get("alg") != "RS256":
        raise ValueError("Unexpected signing algorithm.")
    key_set = jwt.PyJWKSet.from_dict(keys)
    key = next((candidate for candidate in key_set.keys if candidate.key_id == header.get("kid")
                and candidate.key_type == "RSA"), None)
    if key is None:
        raise ValueError("Signing key not found.")
    claims = jwt.decode(id_token, key.key, algorithms=["RS256"], audience=client_id, issuer=ISSUERS,
                        options={"require": ["iss", "aud", "sub", "exp", "iat", "nonce"]}, leeway=30)
    if claims["nonce"] != nonce or claims.get("email_verified") is not True:
        raise ValueError("Google identity was not verified.")
    authorized_party = claims.get("azp")
    if (authorized_party is not None or isinstance(claims["aud"], list) and len(claims["aud"]) > 1
            ) and authorized_party != client_id:
        raise ValueError("Authorized party does not match the app.")
    email = claims.get("email")
    if (not isinstance(email, str) or len(email) > 254
            or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email) or not claims["sub"]):
        raise ValueError("Google identity is incomplete.")
    return claims


def exchange_identity(config: LoginConfig, code: str, verifier: str, nonce: str):
    with httpx.Client(timeout=8, follow_redirects=False, trust_env=False) as client:
        tokens = client.post(GOOGLE_TOKEN, data={
            "client_id": config.client_id, "client_secret": config.secret,
            "redirect_uri": config.redirect, "grant_type": "authorization_code",
            "code": code, "code_verifier": verifier,
        }).raise_for_status().json()
        keys = client.get(JWKS).raise_for_status().json()
    return verify_id_token(tokens["id_token"], keys, config.client_id, nonce)


def google_login_routes(store: Store, config: LoginConfig | None, current_user, session_cookie,
                        start_session, reserve_attempt):
    routes = APIRouter(prefix="/auth/google")
    User = Annotated[dict, Depends(current_user)]

    @routes.get("/status")
    def status():
        return {"configured": config is not None}

    @routes.get("/link")
    def linked(user: User):
        with store.connect() as db:
            identity = db.execute("SELECT email FROM google_identities WHERE user_id = ?", (user["id"],)).fetchone()
        return {"configured": config is not None, "email": identity["email"] if identity else None}

    def begin(request: Request, response: Response, user_id=None):
        if not config:
            raise HTTPException(503, "Google sign-in is not configured.")
        origin = request.headers.get("origin")
        if origin and origin != config.redirect.removesuffix(CALLBACK):
            raise HTTPException(409, "Open SentraTrace at the address configured for Google sign-in.")
        peer = request.client.host if request.client else "unknown"
        reserve_attempt(store, [(f"google-login:{peer}", 20)], 60)
        state, verifier, nonce = (secrets.token_urlsafe(32) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        with store.connect(write=True) as db:
            db.execute("DELETE FROM google_login_attempts WHERE expires <= ?", (int(time.time()),))
            db.execute("INSERT INTO google_login_attempts VALUES (?, ?, ?, ?, ?, ?)", (
                digest(state), verifier, nonce, user_id,
                digest(request.cookies[session_cookie]) if user_id else None, int(time.time()) + 600,
            ))
        response.set_cookie(COOKIE, state, max_age=600, path=CALLBACK,
                            httponly=True, secure=config.secure, samesite="lax")
        return {"url": GOOGLE_AUTH + "?" + urlencode({
            "client_id": config.client_id, "redirect_uri": config.redirect, "response_type": "code",
            "scope": "openid email profile", "prompt": "select_account", "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256", "nonce": nonce,
        })}

    @routes.post("/start")
    def start(request: Request, response: Response):
        return begin(request, response)

    @routes.post("/link")
    def link(user: User, request: Request, response: Response):
        return begin(request, response, user["id"])

    @routes.get("/callback")
    def callback(request: Request, code: str = "", state: str = ""):
        result = RedirectResponse("/login?google=failed", status_code=303,
                                  headers={"Referrer-Policy": "no-referrer"})
        if not config or not 0 < len(state) <= 128 or state != request.cookies.get(COOKIE):
            return result
        result.delete_cookie(COOKIE, path=CALLBACK, httponly=True, secure=config.secure, samesite="lax")
        with store.connect(write=True) as db:
            pending = db.execute("""
                DELETE FROM google_login_attempts WHERE state_hash = ? AND expires > ?
                RETURNING verifier, nonce, user_id, session_hash
            """, (digest(state), int(time.time()))).fetchone()
        if not pending:
            return result
        linking = pending["user_id"] is not None
        if linking:
            result.headers["location"] = "/settings?google=failed"
        if not code or len(code) > 2048:
            return result
        try:
            claims = exchange_identity(config, code, pending["verifier"], pending["nonce"])
        except (httpx.HTTPError, jwt.PyJWTError, KeyError, TypeError, ValueError):
            return result

        subject, email = claims["sub"], claims["email"].lower()
        with store.connect(write=True) as db:
            identity = db.execute("SELECT user_id FROM google_identities WHERE subject = ?", (subject,)).fetchone()
            if linking:
                user_id = pending["user_id"]
                active = db.execute("SELECT 1 FROM sessions WHERE token_hash = ? AND user_id = ? AND expires > ?",
                                    (pending["session_hash"], user_id, int(time.time()))).fetchone()
                if not active:
                    return result
                current_link = db.execute("SELECT subject FROM google_identities WHERE user_id = ?", (user_id,)).fetchone()
                if (identity and identity["user_id"] != user_id) or (current_link and current_link["subject"] != subject):
                    result.headers["location"] = "/settings?google=already-linked"
                    return result
                db.execute("""
                    INSERT INTO google_identities VALUES (?, ?, ?)
                    ON CONFLICT(subject) DO UPDATE SET email = excluded.email
                """, (subject, user_id, email))
                result.headers["location"] = "/settings?google=linked"
                return result

            if identity:
                user_id = identity["user_id"]
            else:
                if db.execute("SELECT 1 FROM users WHERE email = ?", (email,)).fetchone():
                    result.headers["location"] = "/login?google=link-first"
                    return result
                user_id = uuid4().hex
                name = str(claims.get("name") or email.split("@")[0])[:80]
                # OAuth-only users have no usable local password.
                db.execute("INSERT INTO users VALUES (?, ?, ?, ?)", (user_id, email, name, "!"))
                db.execute("INSERT INTO google_identities VALUES (?, ?, ?)", (subject, user_id, email))
            start_session(db, request, result, user_id, "Signed in with Google")
            result.headers["location"] = "/login?google=signed-in"
        return result

    return routes
