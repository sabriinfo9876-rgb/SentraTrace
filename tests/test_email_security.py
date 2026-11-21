import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
from unittest.mock import patch

from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from backend.email_security import CALLBACK, GMAIL, GOOGLE_TOKEN, SCOPE, SENDER, GmailSecurity, alert_kind
from backend.main import create_app
from backend.store import Store

HEADERS = {"X-CyberGuard-Client": "1"}
ACCOUNT = {"name": "Local user", "email": "local@example.test", "password": "test-pass-123"}


def notice(subject: str, auth="mx.google.com; dmarc=pass (p=REJECT) header.from=accounts.google.com"):
    return [{"name": "From", "value": f"Google <{SENDER}>"},
            {"name": "Subject", "value": subject},
            {"name": "Authentication-Results", "value": auth}]


class EmailSecurityTests(unittest.TestCase):
    def setUp(self):
        tmp = self.enterContext(tempfile.TemporaryDirectory())
        self.store = Store(Path(tmp) / "data.sqlite3")
        self.key = Fernet.generate_key()
        self.enterContext(patch.dict("os.environ", {
            "CYBERGUARD_GOOGLE_CLIENT_ID": "fixture-client",
            "CYBERGUARD_GOOGLE_CLIENT_SECRET": "fixture-secret",
            "CYBERGUARD_GOOGLE_REDIRECT_URI": "http://127.0.0.1:8000" + CALLBACK,
            "CYBERGUARD_GOOGLE_TOKEN_KEY": self.key.decode(),
        }))
        # The manual check path goes through the same checker as the periodic worker.
        self.enterContext(patch.object(GmailSecurity, "monitor", autospec=True))
        self.trace = []
        self.enterContext(patch.object(GmailSecurity, "request", side_effect=self.google))
        self.client = self.enterContext(TestClient(create_app(self.store), base_url="http://127.0.0.1:8000"))
        # Use a localhost redirect because Google requires HTTPS outside localhost.
        self.assertEqual(self.client.post("/api/auth/signup", headers=HEADERS, json=ACCOUNT).status_code, 201)

    def google(self, method, url, **details):
        self.trace.append((method, url, details))
        if url == GOOGLE_TOKEN:
            self.assertEqual(details["data"]["client_secret"], "fixture-secret")
            if details["data"]["grant_type"] == "authorization_code":
                self.assertTrue(details["data"]["code_verifier"])
                return {"access_token": "fixture-access", "refresh_token": "fixture-refresh", "scope": SCOPE}
            self.assertEqual(details["data"]["refresh_token"], "fixture-refresh")
            return {"access_token": "fixture-access"}
        if url == f"{GMAIL}/profile":
            return {"emailAddress": "authorized@gmail.com"}
        if url == f"{GMAIL}/messages":
            if details["params"].get("pageToken"):
                return {"messages": [{"id": "general"}]}
            return {"messages": [{"id": "blocked"}, {"id": "spoof"}], "nextPageToken": "second-page"}
        if url.startswith(f"{GMAIL}/messages/"):
            self.assertIn(("format", "metadata"), details["params"])
            message_id = url.split("/")[-1]
            headers = notice("Suspicious sign-in prevented")
            if message_id == "general":
                headers = notice("Critical security alert")
            if message_id == "spoof":
                headers = notice("Suspicious sign-in prevented", "mx.google.com; dmarc=fail header.from=accounts.google.com")
            return {"internalDate": "1795250000000", "payload": {"headers": headers}}
        raise AssertionError(url)

    def start_connect(self):
        connect = self.client.post("/api/email-security/connect", headers=HEADERS)
        self.assertEqual(connect.status_code, 200, connect.text)
        self.assertIn("HttpOnly", connect.headers["set-cookie"])
        query = parse_qs(urlsplit(connect.json()["url"]).query)
        self.assertEqual(query["code_challenge_method"], ["S256"])
        self.assertEqual(query["scope"], [SCOPE])
        return query["state"][0]

    def test_google_consent_scan_notifications_and_disconnect(self):
        state = self.start_connect()
        response = self.client.get(CALLBACK, params={"code": "consent", "state": state}, follow_redirects=False)
        self.assertEqual(response.headers["location"], "/email-security?oauth=connected")
        with self.store.connect() as db:
            ciphertext = db.execute("SELECT refresh_token FROM gmail_connections").fetchone()[0]
        self.assertNotIn(b"fixture-refresh", ciphertext)
        self.assertEqual(Fernet(self.key).decrypt(ciphertext), b"fixture-refresh")
        self.assertEqual(self.client.post("/api/email-security/check", headers=HEADERS).status_code, 200)
        result = self.client.get("/api/email-security").json()
        self.assertEqual(result["connection"]["email"], "authorized@gmail.com")
        self.assertIsNotNone(result["connection"]["last_checked"])
        self.assertEqual(sorted(item["kind"] for item in result["alerts"]),
                         ["Blocked sign-in reported", "Google security activity to review"])
        first_scan_calls = len(self.trace)
        self.client.post("/api/email-security/check", headers=HEADERS)
        self.assertEqual(len(self.trace), first_scan_calls)
        with self.store.connect(write=True) as db:
            db.execute("UPDATE gmail_connections SET next_check = 0")
        self.client.post("/api/email-security/check", headers=HEADERS)
        workspace = self.client.get("/api/workspace").json()
        self.assertEqual(len(workspace["notifs"]), 2)
        self.assertEqual(workspace["stats"]["blocked_attacks"], 0)
        self.assertEqual(self.client.post("/api/notifications/read", headers=HEADERS).status_code, 204)
        self.assertTrue(all(n["read"] for n in self.client.get("/api/workspace").json()["notifs"]))
        self.assertEqual(self.client.post("/api/email-security/disconnect", headers=HEADERS).status_code, 204)
        self.assertEqual(self.client.get("/api/email-security").json(),
                         {"configured": True, "connection": None, "alerts": []})
        self.assertEqual(self.client.get("/api/workspace").json()["notifs"], [])

    def test_callback_requires_browser_state_and_active_session(self):
        state = self.start_connect()
        response = self.client.get(CALLBACK, params={"code": "consent", "state": state + "bad"},
                                   follow_redirects=False)
        self.assertEqual(response.headers["location"], "/email-security?oauth=failed")
        state = self.start_connect()
        self.client.post("/api/auth/logout", headers=HEADERS)
        response = self.client.get(CALLBACK, params={"code": "consent", "state": state}, follow_redirects=False)
        self.assertEqual(response.headers["location"], "/email-security?oauth=failed")
        self.assertEqual(self.trace, [])
        self.assertEqual(self.client.get("/api/email-security").status_code, 401)

    def test_only_supported_authenticated_google_notices_are_classified(self):
        self.assertIsNone(alert_kind(notice("Suspicious sign-in prevented", "sender.test; dmarc=pass header.from=accounts.google.com")))
        self.assertIsNone(alert_kind(notice("Suspicious sign-in prevented", "mx.google.com; dmarc=pass header.from=example.test")))
        self.assertIsNone(alert_kind(notice("Product news")))
        self.assertEqual(alert_kind(notice("Google Security Alert")), "Google security activity to review")
