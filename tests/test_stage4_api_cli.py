"""
Unit tests for Stage 4: REST API HTTP Endpoints and CLI Commands.
Updated to use Bearer token authentication for all protected endpoints.
Standard library only: urllib.request, threading, unittest, tempfile.
"""

import unittest
import sqlite3
import json
import tempfile
import threading
import urllib.request
import urllib.parse
from http.server import HTTPServer
from pathlib import Path

from app.db import init_db, get_connection
from app.server import AccessRequestHandler
from app.audit import record_ledger_event, build_job_seal_payload
from app.crypto import compute_job_seal, JOB_SEAL_KEY, hash_password
from app.cli import cmd_verify, cmd_verify_jobs, cmd_explain, cmd_simulate_grant, cmd_who_could_change
import argparse


class TestStage4ApiAndCli(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.db_path = Path(cls.temp_dir.name) / "test_api.db"
        init_db(cls.db_path)

        # Monkeypatch DB_PATH in modules to point to test DB
        import app.config as config
        import app.db as db_mod
        cls.orig_db_path = config.DB_PATH
        config.DB_PATH = cls.db_path
        db_mod.DB_PATH = cls.db_path

        # Seed test data
        conn = get_connection(cls.db_path)
        pwd_hash, salt = hash_password("TestPass@2026")
        with conn:
            conn.execute(
                "INSERT INTO users (id, username, full_name, password_hash, salt, is_service, is_active, created_at) VALUES (?, ?, ?, ?, ?, 0, 1, datetime('now'))",
                ("admin_dev", "dev", "Dev", pwd_hash, salt),
            )
            conn.execute(
                "INSERT INTO users (id, username, full_name, password_hash, salt, is_service, is_active, created_at) VALUES (?, ?, ?, ?, ?, 0, 1, datetime('now'))",
                ("u_asha", "asha", "Asha", pwd_hash, salt),
            )
            conn.execute(
                "INSERT INTO users (id, username, full_name, password_hash, salt, is_service, is_active, created_at) VALUES (?, ?, ?, ?, ?, 0, 1, datetime('now'))",
                ("u_ravi", "ravi", "Ravi", pwd_hash, salt),
            )
            conn.execute(
                "INSERT INTO users (id, username, full_name, password_hash, salt, is_service, is_active, created_at) VALUES (?, ?, ?, ?, ?, 0, 1, datetime('now'))",
                ("u_other", "other", "Other", pwd_hash, salt),
            )
            conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_ADM', 'admin_dev', 'AccessAdmin', '{}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'sys'),
                       ('G_ASHA_MKR', 'u_asha', 'Maker', '{}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'sys'),
                       ('G_ASHA_CHK', 'u_asha', 'Checker', '{"clients": ["C01"]}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'sys'),
                       ('G_RAVI_CHK', 'u_ravi', 'Checker', '{"clients": ["C02"]}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'sys')
                """
            )
            # Insert jobs
            conn.execute(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, created_at, updated_at)
                VALUES ('J_API_01', 'C01', 'Mumbai', 'import', 'air', 'Confirmed', NULL, datetime('now'), datetime('now')),
                       ('J_API_02', 'C01', 'Mumbai', 'import', 'air', 'Prepared', 'u_other', datetime('now'), datetime('now'))
                """
            )
            # Ledger entry
            record_ledger_event(
                conn, "job_created", "job", "J_API_01", "u_asha", {"client_id": "C01"}
            )
        conn.close()

        # Start HTTP server on localhost free port
        cls.server = HTTPServer(("127.0.0.1", 0), AccessRequestHandler)
        cls.port = cls.server.server_port
        cls.server_thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

        # Login as asha to get a bearer token for tests
        _, login_body = cls._login_static(cls.port, "asha", "TestPass@2026")
        cls.token_asha = login_body.get("token")

        # Login as admin_dev
        _, login_body_admin = cls._login_static(cls.port, "dev", "TestPass@2026")
        cls.token_admin = login_body_admin.get("token")

    @classmethod
    def _login_static(cls, port, username, password):
        """Helper for setUpClass (before instance methods are available)."""
        url = f"http://127.0.0.1:{port}/auth/login"
        data = json.dumps({"username": username, "password": password}).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        import app.config as config
        import app.db as db_mod
        config.DB_PATH = cls.orig_db_path
        db_mod.DB_PATH = cls.orig_db_path
        try:
            cls.temp_dir.cleanup()
        except Exception:
            pass

    def _url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def _post(self, path: str, payload: dict, token: str = None) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self._url(path), data=data, headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8"))
            return e.code, body

    def _get(self, path: str, token: str = None) -> tuple[int, dict]:
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(self._url(path), headers=headers)
        try:
            with urllib.request.urlopen(req) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return resp.status, body
        except urllib.error.HTTPError as e:
            body = json.loads(e.read().decode("utf-8"))
            return e.code, body

    # ------------------------------------------------------------------
    # Auth tests
    # ------------------------------------------------------------------
    def test_auth_login_success(self):
        status, res = self._login_static(self.port, "asha", "TestPass@2026")
        self.assertEqual(status, 200)
        self.assertIn("token", res)
        self.assertIn("user_id", res)
        self.assertEqual(res["user_id"], "u_asha")

    def test_auth_login_bad_password(self):
        status, res = self._login_static(self.port, "asha", "WrongPassword")
        self.assertEqual(status, 401)

    def test_auth_login_unknown_user(self):
        status, res = self._login_static(self.port, "nobody", "pass")
        self.assertEqual(status, 401)

    def test_unauthenticated_request_returns_401(self):
        """Anonymous access to protected endpoints must return 401."""
        status, res = self._get("/audit/verify")
        self.assertEqual(status, 401)

        status2, res2 = self._get("/jobs?limit=5")
        self.assertEqual(status2, 401)

    def test_auth_logout(self):
        """Token should work, then be revoked, then return 401."""
        # Login fresh
        status, body = self._login_static(self.port, "asha", "TestPass@2026")
        temp_token = body["token"]
        # Use the token
        s1, _ = self._get("/audit/verify", token=temp_token)
        self.assertEqual(s1, 200)
        # Logout
        s2, _ = self._post("/auth/logout", {}, token=temp_token)
        self.assertEqual(s2, 200)
        # Revoked token should 401
        s3, _ = self._get("/audit/verify", token=temp_token)
        self.assertEqual(s3, 401)

    # ------------------------------------------------------------------
    # Existing functionality tests (now with auth tokens)
    # ------------------------------------------------------------------
    def test_api_authorize_allow_and_deny(self):
        # Asha preparing Confirmed job J_API_01 -> ALLOW
        # actor_id comes from verified session, not the body
        status, res = self._post(
            "/authorize",
            {"action": "prepare", "job_id": "J_API_01"},
            token=self.token_asha,
        )
        self.assertEqual(status, 200)
        self.assertEqual(res["decision"], "ALLOW")
        self.assertTrue("signature" in res)

        # Asha checking Confirmed job J_API_01 -> DENY (stage invalid)
        status, res = self._post(
            "/authorize",
            {"action": "check", "job_id": "J_API_01"},
            token=self.token_asha,
        )
        self.assertEqual(status, 403)
        self.assertEqual(res["decision"], "DENY")
        self.assertEqual(res["code"], "DENIED_BY_STAGE")

    def test_api_actor_id_in_body_ignored(self):
        """Submitting actor_id in request body must not override session identity."""
        # Login as ravi (Checker for C02 only)
        _, ravi_login = self._login_static(self.port, "ravi", "TestPass@2026")
        ravi_token = ravi_login["token"]

        # Submit actor_id=u_asha in body — should use ravi's verified session identity
        # Ravi does NOT have prepare permission on J_API_01 (not a Maker)
        # but if actor_id from body were trusted it would use asha's perms
        status, res = self._post(
            "/authorize",
            {"action": "prepare", "job_id": "J_API_01", "actor_id": "u_asha"},
            token=ravi_token,
        )
        # Ravi authenticated, decision should use ravi's identity (Checker only)
        # Ravi doesn't have prepare on C01 → DENY
        self.assertEqual(res["decision"], "DENY")

    def test_api_jobs_waiting(self):
        # For Asha: J_API_01 is Confirmed (Asha is Maker -> waiting)
        status, res = self._get("/jobs/waiting?user=u_asha", token=self.token_asha)
        self.assertEqual(status, 200)
        self.assertEqual(res["user_id"], "u_asha")
        self.assertGreaterEqual(res["waiting_count"], 1)

    def test_api_jobs_keyset_pagination(self):
        status, res = self._get("/jobs?limit=1", token=self.token_asha)
        self.assertEqual(status, 200)
        self.assertEqual(len(res["jobs"]), 1)
        next_after = res["next_after"]
        self.assertIsNotNone(next_after)

        status2, res2 = self._get(f"/jobs?limit=1&after={next_after}", token=self.token_asha)
        self.assertEqual(status2, 200)
        self.assertEqual(len(res2["jobs"]), 1)
        self.assertNotEqual(res["jobs"][0]["id"], res2["jobs"][0]["id"])

    def test_shipments_page_prompts_for_authenticated_access(self):
        req = urllib.request.Request(self._url("/shipments"))
        with urllib.request.urlopen(req) as resp:
            page = resp.read().decode("utf-8")

        self.assertEqual(resp.status, 200)
        self.assertIn('id="explorerLoginForm"', page)
        self.assertIn('id="explorerLoginPanel"', page)
        self.assertIn("Authorization", page)
        self.assertNotIn("as_user=u_priya", page)

    def test_api_jobs_limit_zero_rejected(self):
        """limit=0 must be rejected with 400."""
        status, res = self._get("/jobs?limit=0", token=self.token_asha)
        self.assertEqual(status, 400)

    def test_api_explain(self):
        # Explain why Asha can check J_API_02 (client C01) and Ravi cannot (Ravi is Checker for C02)
        status, res = self._get(
            "/explain?user=u_asha&other=u_ravi&action=check&job=J_API_02",
            token=self.token_admin,
        )
        self.assertEqual(status, 200)
        self.assertEqual(res["user_a"]["decision"], "ALLOW")
        self.assertEqual(res["user_b"]["decision"], "DENY")
        self.assertIn("u_asha is ALLOW", res["comparison_summary"])

    def test_api_audit_verify(self):
        status, res = self._get("/audit/verify", token=self.token_asha)
        self.assertEqual(status, 200)
        self.assertTrue(res["is_ledger_valid"])

    def test_api_audit_verify_jobs(self):
        status, res = self._get("/audit/verify-jobs", token=self.token_admin)
        self.assertEqual(status, 200)
        self.assertIn("is_clean", res)
        self.assertIn("tampered_count", res)

    def test_api_root_dashboard(self):
        # 1. HTML Dashboard — public, no auth needed
        req = urllib.request.Request(self._url("/"))
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type", ""))
            html = resp.read().decode("utf-8")
            self.assertIn("Tez Adhikar", html)

        # 2. JSON Index — returns without auth (limited info)
        status, res = self._get("/?format=json")
        self.assertEqual(status, 200)
        self.assertEqual(res["product_name"], "Tez Adhikar")
        self.assertEqual(res["service"], "Tez Adhikar — Access Control & Audit Service")
        self.assertIn("status", res)

    def test_cli_functions(self):
        # Test CLI simulate-grant
        args = argparse.Namespace(
            grantor="admin_dev",
            user="u_ravi",
            role="Maker",
            scope='{"branches": ["Mumbai"]}',
        )
        cmd_simulate_grant(args)


if __name__ == "__main__":
    unittest.main()
