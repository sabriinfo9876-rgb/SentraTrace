import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import httpx
from fastapi.testclient import TestClient

from backend.main import create_app, digest
from backend.store import Store


HEADERS = {"X-CyberGuard-Client": "1"}
STORE = "/api/integrations/ma-hijab"
ACCOUNT = {"email": "owner@example.test", "name": "Store Owner", "password": "fixture-password"}


class CopilotStoreTests(unittest.TestCase):
    def setUp(self):
        path = Path(self.enterContext(tempfile.TemporaryDirectory())) / "app.sqlite3"
        self.store = Store(path)
        self.app = create_app(self.store, dist=path.parent / "no-frontend")
        self.client = self.enterContext(TestClient(self.app))
        self.enterContext(patch.dict("os.environ", {"CYBERGUARD_GEMINI_API_KEY": ""}))

    def signup(self, client, email=ACCOUNT["email"]):
        response = client.post("/api/auth/signup", headers=HEADERS, json={**ACCOUNT, "email": email})
        self.assertEqual(response.status_code, 201)

    def send(self, token, route="customer-login"):
        return self.client.post(STORE + "/events", headers={**HEADERS, "Authorization": f"Bearer {token}"},
                                json={"route": route})

    def test_store_tokens_are_hashed_rotatable_and_workspace_scoped(self):
        self.assertEqual(self.client.post(STORE + "/key", headers=HEADERS).status_code, 401)
        self.signup(self.client)
        key = self.client.post(STORE + "/key", headers=HEADERS).json()["key"]
        self.assertEqual(self.client.get(STORE).json(), {"configured": True})
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT token_hash FROM store_connection").fetchone()[0], digest(key))
        self.assertEqual(self.send("invalid").status_code, 401)
        self.assertEqual(self.send(key, "invalid").status_code, 422)
        event_id = self.send(key).json()["id"]
        data = self.client.get("/api/workspace").json()
        self.assertEqual(data["events"][0]["id"], event_id)
        self.assertEqual(data["events"][0]["source"], "Live")
        self.assertEqual(data["events"][0]["resource"], "M.A-HIJAB /api/auth/login")
        self.assertEqual(data["stats"]["blocked_attacks"], 1)
        self.assertEqual(len(data["notifs"]), 1)
        with TestClient(self.app) as another:
            self.signup(another, "second@example.test")
            self.assertEqual(another.get("/api/workspace").json()["events"], [])
        replacement = self.client.post(STORE + "/key", headers=HEADERS).json()["key"]
        self.assertEqual(self.send(key).status_code, 401)
        self.assertEqual(self.send(replacement, "admin-login").status_code, 201)

    def test_connection_check_is_authenticated_and_does_not_record_events(self):
        check = STORE + "/check"
        self.signup(self.client)
        self.assertEqual(self.client.get(check).status_code, 401)
        key = self.client.post(STORE + "/key", headers=HEADERS).json()["key"]
        self.assertEqual(self.client.get(check, headers={"Authorization": "Bearer invalid"}).status_code, 401)
        response = self.client.get(check, headers={"Authorization": f"Bearer {key}"})
        self.assertEqual(response.json(), {"status": "connected"})
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertEqual(self.client.get("/api/workspace").json()["events"], [])
        self.client.post(STORE + "/key", headers=HEADERS)
        self.assertEqual(self.client.get(check, headers={"Authorization": f"Bearer {key}"}).status_code, 401)

    def test_copilot_reads_account_events_and_labels_real_and_preview_counts(self):
        payload = {"message": "Incidents ka khulasa", "language": "roman"}
        self.assertEqual(self.client.post("/api/copilot", headers=HEADERS, json=payload).status_code, 401)
        self.signup(self.client)
        self.client.post("/api/simulate/bola", headers=HEADERS)
        result = self.client.post("/api/copilot", headers=HEADERS, json=payload).json()
        self.assertEqual(result["mode"], "workspace")
        self.assertIn("Live: 0 · Preview: 1", result["text"])
        self.assertEqual(self.client.post("/api/copilot", headers=HEADERS, json={"message": " "}).status_code, 422)

    def test_gemini_gets_only_approved_help_and_failure_returns_local_reply(self):
        self.signup(self.client)
        payload = {"message": "Explain account ownership. Random input 123", "language": "en"}
        upstream = Mock()
        upstream.post.return_value.raise_for_status.return_value.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "Check account ownership on the server."}]}}]
        }
        with patch.dict("os.environ", {"CYBERGUARD_GEMINI_API_KEY": "test-only"}):
            with patch("backend.copilot.httpx.Client") as client_factory:
                client_factory.return_value.__enter__.return_value = upstream
                result = self.client.post("/api/copilot", headers=HEADERS, json=payload).json()
                self.assertEqual(result["mode"], "gemini")
                self.assertNotIn("Random input 123", str(upstream.post.call_args.kwargs["json"]))
                upstream.post.side_effect = httpx.ConnectError("mock outage")
                result = self.client.post("/api/copilot", headers=HEADERS, json=payload).json()
                self.assertEqual(result["mode"], "fallback")
                self.assertIn("ownership", result["text"])
