import tempfile
import time
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

from backend.defense import LOGIN_LIMIT, LOGIN_WINDOW
from backend.main import COOKIE, WORKSPACE_HEADER, create_app, digest
from backend.store import Store

HEADERS = {"X-CyberGuard-Client": "1"}
ACCOUNT = {"name": "Demo Analyst", "email": "analyst@example.test", "password": "fixture-password"}


class BackendTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.store = Store(Path(self.temp.name) / "test.sqlite3")
        self.app = create_app(self.store, dist=Path(self.temp.name) / "no-frontend")
        self.client = self.enterContext(TestClient(self.app))

    def sign_up(self, client=None, account=None):
        client = self.client if client is None else client
        result = client.post("/api/auth/signup", headers=HEADERS, json=account or ACCOUNT)
        self.assertEqual(result.status_code, 201, result.text)
        return result

    def snapshot(self, client=None):
        client = self.client if client is None else client
        result = client.get("/api/workspace")
        self.assertEqual(result.status_code, 200)
        return result.json()

    def test_session_lifecycle_and_revocation(self):
        for path in ("/api/auth/me", "/api/workspace", "/api/accounts/me", "/api/policies"):
            self.assertEqual(self.client.get(path).status_code, 401)
        result = self.sign_up()
        self.assertIn("HttpOnly", result.headers["set-cookie"])
        self.assertIn("SameSite=strict", result.headers["set-cookie"])
        self.assertEqual(result.headers["cache-control"], "no-store")
        user = result.json()
        token = self.client.cookies.get(COOKIE)
        self.assertEqual(self.client.get("/api/auth/me").json(), user)
        self.assertEqual(self.client.post("/api/auth/logout", headers=HEADERS).status_code, 204)
        self.client.cookies.set(COOKIE, token)
        self.assertEqual(self.client.get("/api/auth/me").status_code, 401)
        self.client.cookies.clear()
        bad = self.client.post("/api/auth/login", headers=HEADERS, json={**ACCOUNT, "password": "wrong"})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(self.client.post("/api/auth/login", headers=HEADERS, json=ACCOUNT).json(), user)

    def test_input_origin_and_duplicates(self):
        self.assertEqual(self.client.post("/api/auth/signup", json=ACCOUNT).status_code, 403)
        cross_site = {**HEADERS, "Sec-Fetch-Site": "same-site"}
        self.assertEqual(self.client.post("/api/auth/signup", headers=cross_site, json=ACCOUNT).status_code, 403)
        invalid = self.client.post("/api/auth/signup", headers=HEADERS, json={**ACCOUNT, "password": "tiny"})
        self.assertEqual(invalid.status_code, 422)
        self.assertNotIn("tiny", invalid.text)
        self.sign_up()
        duplicate = self.client.post("/api/auth/signup", headers=HEADERS,
                                     json={**ACCOUNT, "email": ACCOUNT["email"].upper()})
        self.assertEqual(duplicate.status_code, 409)

    def test_live_account_access_and_workspace_separation(self):
        first = self.sign_up().json()
        with TestClient(self.app) as second:
            second_user = self.sign_up(second, {**ACCOUNT, "email": "second@example.test"}).json()
            self.assertEqual(self.client.get("/api/accounts/me").json(), first)
            self.assertEqual(second.get("/api/accounts/me").json(), second_user)
            denied = self.client.get(f"/api/accounts/{second_user['id']}")
            missing = self.client.get("/api/accounts/missing")
            self.assertEqual((denied.status_code, denied.json()), (missing.status_code, missing.json()))
            self.assertEqual(denied.status_code, 404)
            data = self.snapshot()
            self.assertEqual(data["stats"]["total_requests"], 3)
            self.assertEqual(data["stats"]["blocked_attacks"], 2)
            self.assertTrue(all(event["source"] == "Live" for event in data["events"]))
            self.assertEqual(self.snapshot(second)["stats"]["total_requests"], 1)
            self.assertEqual(self.snapshot(second)["notifs"], [])

    def test_policy_previews_and_persisted_notifications(self):
        self.sign_up()
        for kind in ("bola", "brute-force"):
            result = self.client.post(f"/api/simulate/{kind}", headers=HEADERS)
            self.assertEqual(result.status_code, 200)
            self.assertEqual(result.json()["defender_action"], "Blocked")
            self.assertEqual(result.json()["raw"]["source"], "Preview")
        data = self.snapshot()
        self.assertEqual(data["stats"]["threats_detected"], 2)
        self.assertEqual(len(data["notifs"]), 2)
        self.assertEqual(len(data["audit"]), 3)
        self.assertEqual(self.client.post("/api/notifications/read", headers=HEADERS).status_code, 204)
        with TestClient(create_app(self.store)) as restarted:
            restarted.cookies.set(COOKIE, self.client.cookies.get(COOKIE))
            self.assertTrue(all(note["read"] for note in self.snapshot(restarted)["notifs"]))
            self.assertEqual(restarted.post("/api/notifications/clear", headers=HEADERS).status_code, 204)
        self.assertEqual(self.snapshot()["notifs"], [])
        self.assertEqual(len(self.snapshot()["events"]), 2)

    def test_login_at_rate_limit(self):
        self.sign_up()
        with self.store.connect(write=True) as db:
            db.execute("INSERT INTO rate_limits VALUES (?, ?, ?)",
                       (f"login:identity:testclient:{digest(ACCOUNT['email'])}",
                        LOGIN_LIMIT, int(time.time()) + LOGIN_WINDOW))
        response = self.client.post("/api/auth/login", headers=HEADERS, json=ACCOUNT)
        self.assertEqual(response.status_code, 429)
        self.assertGreater(int(response.headers["Retry-After"]), 0)

    def test_session_expiry(self):
        self.sign_up()
        with self.store.connect(write=True) as db:
            db.execute("UPDATE sessions SET expires = 0")
        self.assertEqual(self.client.get("/api/workspace").status_code, 401)

    def test_health_reports_actual_storage_and_auth(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["database"], "SQLite")
        self.assertEqual(response.json()["authentication"], "Local email/password")

    def test_stale_workspace_context_cannot_act_using_new_session(self):
        previous_user = self.sign_up().json()
        current_user = self.sign_up(account={**ACCOUNT, "email": "new@example.test"}).json()
        stale_headers = {**HEADERS, WORKSPACE_HEADER: previous_user["id"]}
        for path in ("/api/workspace", "/api/accounts/me", "/api/policies"):
            self.assertEqual(self.client.get(path, headers=stale_headers).status_code, 401)
        for path in ("/api/simulate/bola", "/api/notifications/clear", "/api/auth/logout"):
            self.assertEqual(self.client.post(path, headers=stale_headers).status_code, 401)
        self.assertEqual(self.client.get("/api/auth/me").json(), current_user)
        self.assertEqual(self.snapshot()["events"], [])
        current_headers = {**HEADERS, WORKSPACE_HEADER: current_user["id"]}
        self.assertEqual(self.client.post("/api/simulate/bola", headers=current_headers).status_code, 200)
        self.assertEqual(len(self.snapshot()["events"]), 1)


if __name__ == "__main__":
    unittest.main()
