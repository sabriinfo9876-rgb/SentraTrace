import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from backend.google_login import CALLBACK, verify_id_token
from backend.main import create_app
from backend.store import Store

HEADERS = {"X-CyberGuard-Client": "1"}
LOCAL = {"name": "Existing", "email": "owner@gmail.com", "password": "fixture-password"}


class GoogleLoginTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.store = Store(Path(tmp) / "test.sqlite3")
        self.enterContext(patch.dict("os.environ", {
            "CYBERGUARD_GOOGLE_CLIENT_ID": "client",
            "CYBERGUARD_GOOGLE_CLIENT_SECRET": "secret",
            "CYBERGUARD_GOOGLE_LOGIN_REDIRECT_URI": "http://127.0.0.1:8000" + CALLBACK,
        }))
        self.identity = {"sub": "stable-google-sub", "email": LOCAL["email"], "name": "Provider User"}
        self.exchange = self.enterContext(patch("backend.google_login.exchange_identity",
                                               side_effect=lambda *args: self.identity))
        self.client = self.enterContext(TestClient(create_app(self.store), base_url="http://127.0.0.1:8000"))

    def begin(self, path="/start"):
        result = self.client.post("/api/auth/google" + path, headers=HEADERS)
        self.assertEqual(result.status_code, 200, result.text)
        params = parse_qs(urlsplit(result.json()["url"]).query)
        self.assertEqual(params["scope"], ["openid email profile"])
        self.assertEqual(params["code_challenge_method"], ["S256"])
        self.assertTrue(params["nonce"][0])
        return params["state"][0]

    def finish(self, state):
        return self.client.get(CALLBACK, params={"code": "fixture-code", "state": state},
                               follow_redirects=False).headers["location"]

    def test_new_google_user_can_sign_in_again_by_stable_subject(self):
        self.assertEqual(self.client.get("/api/auth/google/status").json(), {"configured": True})
        state = self.begin()
        self.assertEqual(self.finish(state), "/login?google=signed-in")
        user = self.client.get("/api/auth/me").json()
        self.assertEqual(user["email"], LOCAL["email"])
        self.assertEqual(self.finish(state), "/login?google=failed")
        self.assertEqual(self.exchange.call_count, 1)
        self.assertEqual(self.client.post("/api/auth/logout", headers=HEADERS).status_code, 204)
        self.assertEqual(self.client.post("/api/auth/login", headers=HEADERS, json=LOCAL).status_code, 401)
        self.identity["email"] = "changed@gmail.com"
        self.assertEqual(self.finish(self.begin()), "/login?google=signed-in")
        self.assertEqual(self.client.get("/api/auth/me").json()["id"], user["id"])

    def test_matching_email_is_never_linked_without_local_session(self):
        created = self.client.post("/api/auth/signup", headers=HEADERS, json=LOCAL)
        self.assertEqual(created.status_code, 201)
        self.client.post("/api/simulate/bola", headers=HEADERS)
        self.client.post("/api/auth/logout", headers=HEADERS)
        self.assertEqual(self.finish(self.begin()), "/login?google=link-first")
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.assertEqual(self.client.post("/api/auth/login", headers=HEADERS, json=LOCAL).status_code, 200)
        self.assertEqual(self.finish(self.begin("/link")), "/settings?google=linked")
        self.client.post("/api/auth/logout", headers=HEADERS)
        self.assertEqual(self.finish(self.begin()), "/login?google=signed-in")
        self.assertEqual(self.client.get("/api/auth/me").json()["id"], created.json()["id"])
        self.assertEqual(self.client.get("/api/workspace").json()["stats"]["total_requests"], 1)

    def test_callback_requires_browser_state_and_original_link_session(self):
        state = self.begin()
        self.assertEqual(self.finish(state + "wrong"), "/login?google=failed")
        self.exchange.assert_not_called()
        self.client.post("/api/auth/signup", headers=HEADERS, json=LOCAL)
        state = self.begin("/link")
        self.client.post("/api/auth/logout", headers=HEADERS)
        self.assertEqual(self.finish(state), "/settings?google=failed")
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM google_identities").fetchone()[0], 0)

    def test_id_token_signature_audience_nonce_and_verified_email(self):
        signing_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key()))
        jwk["kid"] = "key"
        keys = {"keys": [jwk]}
        now = int(time.time())
        claims = {"iss": "https://accounts.google.com", "aud": "client", "sub": "identity",
                  "iat": now, "exp": now + 100, "nonce": "expected", "email": LOCAL["email"],
                  "email_verified": True}

        def verify(**changes):
            token = jwt.encode({**claims, **changes}, signing_key, algorithm="RS256", headers={"kid": "key"})
            return verify_id_token(token, keys, "client", "expected")

        self.assertEqual(verify()["sub"], "identity")
        for changes in ({"aud": "other-client"}, {"nonce": "wrong"}, {"email_verified": False},
                        {"exp": now - 100}, {"iss": "https://other.example"}):
            with self.subTest(changes=changes), self.assertRaises((jwt.PyJWTError, ValueError)):
                verify(**changes)
