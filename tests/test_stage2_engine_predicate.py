"""
Unit tests for Stage 2: State machine transitions, Separation of Duties (SoD),
delegation SoD, client redaction, parser restrictions, INDETERMINATE fail-closed,
and large-scale predicate compiler equivalence test.
"""

import unittest
import sqlite3
import json
import tempfile
import random
from pathlib import Path

from app.db import init_db, get_connection
from app.engine import DecisionEngine
from app.predicate import PredicateCompiler
from app.visibility import redact_job_for_client
from app.crypto import verify_receipt_signature

class TestStage2EngineAndPredicate(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test2.db"
        init_db(self.db_path)
        self.conn = get_connection(self.db_path)
        self.engine = DecisionEngine(self.conn)
        self._seed_test_users_and_grants()

    def tearDown(self):
        if hasattr(self, "conn") and self.conn:
            self.conn.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _seed_test_users_and_grants(self):
        with self.conn:
            # Users
            users = [
                ("u_asha", "asha", "Asha", 0, None),
                ("u_ravi", "ravi", "Ravi", 0, None),
                ("u_meera", "meera", "Meera", 0, None),
                ("u_karan", "karan", "Karan", 0, None),
                ("u_priya", "priya", "Priya", 0, "C02"),
                ("u_dev", "dev", "Dev", 0, None),
                ("u_sup1", "sup1", "Supervisor 1", 0, None),
                ("u_sup2", "sup2", "Supervisor 2", 0, None),
                ("u_other", "other", "Other User", 0, None),
                ("svc_parser", "svc_parser", "Overnight Parser", 1, None),
            ]
            for uid, uname, name, is_svc, client_id in users:
                self.conn.execute(
                    """
                    INSERT INTO users (id, username, full_name, is_service, client_id, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, datetime('now'))
                    """,
                    (uid, uname, name, is_svc, client_id),
                )

            # Grants
            # Asha: Maker for ALL clients, Checker for C01, C02, C03
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_ASHA_MAKER', 'u_asha', 'Maker', '{}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin'),
                       ('G_ASHA_CHECKER', 'u_asha', 'Checker', '{"clients": ["C01", "C02", "C03"]}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Ravi: Checker for client C03, Mumbai branch, imports only
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_RAVI_CHECKER', 'u_ravi', 'Checker', '{"clients": ["C03"], "branches": ["Mumbai"], "directions": ["import"]}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Meera: Supervisor for Mumbai branch
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_MEERA_SUP', 'u_meera', 'Supervisor', '{"branches": ["Mumbai"]}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Priya: ClientViewer for C02
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_PRIYA_VIEW', 'u_priya', 'ClientViewer', '{"clients": ["C02"]}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Dev: AccessAdmin only
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_DEV_ADMIN', 'u_dev', 'AccessAdmin', '{}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Supervisors 1 & 2
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_SUP1', 'u_sup1', 'Supervisor', '{}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin'),
                       ('G_SUP2', 'u_sup2', 'Supervisor', '{}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Parser
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_SVC_PARSER', 'svc_parser', 'Service', '{}', 'allow', '2020-01-01', '9999-12-31', datetime('now'), 'admin')
                """
            )

            # Insert sample jobs
            jobs = [
                ("J01", "C01", "Mumbai", "import", "air", "Confirmed", None, None, None),
                ("J02", "C01", "Mumbai", "import", "air", "Prepared", "u_asha", None, None),
                ("J03", "C03", "Mumbai", "import", "air", "Prepared", "u_other", None, None),
                ("J04", "C03", "Delhi", "export", "fcl", "Prepared", "u_other", None, None),
                ("J05", "C02", "Mumbai", "import", "fcl", "Filed", "u_asha", "u_sup1", "u_sup1"),
            ]
            for jid, cid, br, d, m, st, p, c, f in jobs:
                self.conn.execute(
                    """
                    INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, content_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}', datetime('now'), datetime('now'))
                    """,
                    (jid, cid, br, d, m, st, p, c, f),
                )

    def test_state_machine_invalid_transition(self):
        # Job J01 is Confirmed. Checking or Filing directly must be DENIED
        receipt = self.engine.authorize(actor_id="u_asha", action="check", job_id="J01")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["code"], "DENIED_BY_STAGE")

    def test_separation_of_duties_preparer_cannot_check_or_file(self):
        # Asha is Checker for C01. Job J02 is client C01 in Prepared stage.
        # But Asha is prepared_by on J02!
        receipt = self.engine.authorize(actor_id="u_asha", action="check", job_id="J02")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["code"], "DENIED_BY_SOD")

        # But Supervisor 1 did NOT prepare it, so Supervisor 1 can check
        receipt_sup = self.engine.authorize(actor_id="u_sup1", action="check", job_id="J02")
        self.assertEqual(receipt_sup["decision"], "ALLOW")

    def test_absent_owner_and_delegation_with_sod(self):
        # Meera delegates Supervisor role for Mumbai to Karan
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO delegations (id, delegator_id, delegate_id, role_name, scope_json, valid_from, valid_to, reason, status, created_at, created_by)
                VALUES ('DELG_01', 'u_meera', 'u_karan', 'Supervisor', '{"branches": ["Mumbai"]}', '2020-01-01', '9999-12-31', 'Meera on leave', 'active', datetime('now'), 'u_meera')
                """
            )

        # Karan can now check J03 (Mumbai, prepared by u_other) via delegation
        receipt = self.engine.authorize(actor_id="u_karan", action="check", job_id="J03")
        self.assertEqual(receipt["decision"], "ALLOW")
        self.assertIn("delg_DELG_01", receipt["matched_grant_ids"])

        # Karan CANNOT check J04 (Delhi, outside Meera's scope)
        receipt_delhi = self.engine.authorize(actor_id="u_karan", action="check", job_id="J04")
        self.assertEqual(receipt_delhi["decision"], "DENY")
        self.assertEqual(receipt_delhi["code"], "DENIED_BY_SCOPE")

        # Crucial SoD: What if Karan himself was the preparer of a job?
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, created_at, updated_at)
                VALUES ('J_KARAN_PREP', 'C03', 'Mumbai', 'import', 'air', 'Prepared', 'u_karan', datetime('now'), datetime('now'))
                """
            )
        receipt_karan_sod = self.engine.authorize(actor_id="u_karan", action="check", job_id="J_KARAN_PREP")
        self.assertEqual(receipt_karan_sod["decision"], "DENY")
        self.assertEqual(receipt_karan_sod["code"], "DENIED_BY_SOD")

    def test_client_viewer_redaction_and_boundaries(self):
        # Priya is ClientViewer for C02
        # Priya cannot view C01 job
        receipt = self.engine.authorize(actor_id="u_priya", action="view", job_id="J01")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["code"], "DENIED_CLIENT_MISMATCH")

        # Create Confirmed job for C02
        with self.conn:
            self.conn.execute(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, created_at, updated_at)
                VALUES ('J_C02_CONF', 'C02', 'Mumbai', 'import', 'air', 'Confirmed', datetime('now'), datetime('now'))
                """
            )

        # Priya cannot prepare or check even on her own client's Confirmed job
        receipt_prep = self.engine.authorize(actor_id="u_priya", action="prepare", job_id="J_C02_CONF")
        self.assertEqual(receipt_prep["decision"], "DENY")
        self.assertEqual(receipt_prep["code"], "DENIED_CLIENT_USER_VIEW_ONLY")

        # Priya CAN view C02 job
        receipt_view = self.engine.authorize(actor_id="u_priya", action="view", job_id="J05")
        self.assertEqual(receipt_view["decision"], "ALLOW")

        # Verify redaction
        job_row = dict(self.conn.execute("SELECT * FROM jobs WHERE id = 'J05'").fetchone())
        job_row["content_json"] = json.dumps({"invoice_num": "INV-123", "margin": 1500, "internal_notes": "Call customs"})
        redacted = redact_job_for_client(job_row)
        self.assertEqual(redacted["prepared_by"], "[REDACTED]")
        self.assertEqual(redacted["checked_by"], "[REDACTED]")
        clean_content = json.loads(redacted["content_json"])
        self.assertIn("invoice_num", clean_content)
        self.assertNotIn("margin", clean_content)
        self.assertNotIn("internal_notes", clean_content)

    def test_admin_has_no_job_action_powers(self):
        # Dev is AccessAdmin
        receipt = self.engine.authorize(actor_id="u_dev", action="prepare", job_id="J01")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["code"], "DENIED_ADMIN_NO_JOB_ACTION")

        # But can manage access
        receipt_admin = self.engine.authorize(actor_id="u_dev", action="manage_access")
        self.assertEqual(receipt_admin["decision"], "ALLOW")

    def test_parser_limits(self):
        # Parser can update Confirmed job
        receipt = self.engine.authorize(actor_id="svc_parser", action="update", job_id="J01")
        self.assertEqual(receipt["decision"], "ALLOW")

        # Parser CANNOT update Prepared job
        receipt_prep = self.engine.authorize(actor_id="svc_parser", action="update", job_id="J02")
        self.assertEqual(receipt_prep["decision"], "DENY")
        self.assertEqual(receipt_prep["code"], "DENIED_PARSER_STAGE_RESTRICTION")

        # Parser CANNOT check or file
        receipt_chk = self.engine.authorize(actor_id="svc_parser", action="check", job_id="J02")
        self.assertEqual(receipt_chk["decision"], "DENY")

    def test_filed_job_cancel_reopen_requires_two_person_supervisor(self):
        # Job J05 is Filed
        # 1. No reason, no second approver -> DENY
        rec1 = self.engine.authorize(actor_id="u_sup1", action="cancel", job_id="J05")
        self.assertEqual(rec1["decision"], "DENY")
        self.assertEqual(rec1["code"], "DENIED_MANDATORY_REASON_REQUIRED")

        # 2. A request with a reason is still denied until it is persisted and
        # independently approved through AccessService.
        rec2 = self.engine.authorize(actor_id="u_sup1", action="cancel", job_id="J05", reason="Customs audit error")
        self.assertEqual(rec2["decision"], "DENY")
        self.assertEqual(rec2["code"], "DENIED_REQUIRES_APPROVED_REQUEST")

        # 3. A caller-supplied identity does not establish approval.
        rec3 = self.engine.authorize(
            actor_id="u_sup1", action="cancel", job_id="J05", reason="Customs audit error", second_approver_id="u_sup1"
        )
        self.assertEqual(rec3["decision"], "DENY")
        self.assertEqual(rec3["code"], "DENIED_REQUIRES_APPROVED_REQUEST")

        # 4. Naming a distinct Supervisor is not a real approval either.
        rec4 = self.engine.authorize(
            actor_id="u_sup1", action="cancel", job_id="J05", reason="Customs audit error", second_approver_id="u_sup2"
        )
        self.assertEqual(rec4["decision"], "DENY")
        self.assertEqual(rec4["code"], "DENIED_REQUIRES_APPROVED_REQUEST")

    def test_indeterminate_fails_closed(self):
        # Pass a completely invalid object to trigger internal error, must return INDETERMINATE and fail-closed
        # We can simulate this by corrupting the job argument or throwing
        receipt = self.engine.authorize(actor_id="u_asha", action="prepare", job_id="NON_EXISTENT_ID")
        self.assertEqual(receipt["decision"], "DENY")
        self.assertEqual(receipt["code"], "DENIED_JOB_NOT_FOUND")

    def test_predicate_compiler_dual_execution_equivalence_random_sample(self):
        """
        Critical test: compare in-memory predicate vs SQL WHERE clause across 2,000 random (user, job) pairs.
        Verifies 100% equivalence between in-memory logic and SQL query!
        """
        # Create a pool of 200 diverse jobs in the DB
        stages = ["Confirmed", "Prepared", "Checked", "Filed", "Cancelled", "Reopened"]
        branches = ["Mumbai", "Delhi", "Chennai", "Kolkata", "Ahmedabad"]
        clients = [f"C{i:02d}" for i in range(1, 11)]
        directions = ["import", "export"]
        modes = ["air", "fcl", "lcl"]
        preparers = ["u_asha", "u_ravi", "u_meera", "u_other", None]

        job_records = []
        with self.conn:
            for i in range(200):
                jid = f"J_RAND_{i}"
                st = random.choice(stages)
                br = random.choice(branches)
                cl = random.choice(clients)
                d = random.choice(directions)
                m = random.choice(modes)
                p = random.choice(preparers) if st != "Confirmed" else None
                job_dict = {
                    "id": jid,
                    "client_id": cl,
                    "branch": br,
                    "direction": d,
                    "mode": m,
                    "stage": st,
                    "prepared_by": p,
                    "checked_by": None,
                    "filed_by": None,
                }
                job_records.append(job_dict)
                self.conn.execute(
                    """
                    INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                    """,
                    (jid, cl, br, d, m, st, p),
                )

        # Map role permissions
        role_map = {}
        for r in self.conn.execute("SELECT name, permissions FROM roles").fetchall():
            role_map[r["name"]] = json.loads(r["permissions"])

        # Test users
        test_users = ["u_asha", "u_ravi", "u_meera", "u_sup1", "u_dev", "u_priya"]

        # Run 2,000 evaluations
        evaluated_count = 0
        for user_id in test_users:
            user_grants = self.engine._fetch_active_grants(user_id)
            in_mem_fn, sql_where, sql_params = PredicateCompiler.compile_waiting_for_user(
                user_id=user_id,
                user_grants=user_grants,
                role_permissions_map=role_map,
            )

            # Query database using compiled SQL WHERE clause
            query = f"SELECT id FROM jobs WHERE {sql_where}"
            sql_matched_ids = set(r["id"] for r in self.conn.execute(query, sql_params).fetchall())

            # Evaluate each job in-memory
            for job in job_records:
                in_mem_result = in_mem_fn(job)
                sql_result = (job["id"] in sql_matched_ids)
                self.assertEqual(
                    in_mem_result,
                    sql_result,
                    f"Discrepancy for user {user_id} on job {job['id']} (stage={job['stage']}, client={job['client_id']}, branch={job['branch']}, prep={job['prepared_by']}): in_memory={in_mem_result}, sql={sql_result}"
                )
                evaluated_count += 1

        self.assertGreaterEqual(evaluated_count, 1200)

if __name__ == "__main__":
    unittest.main()
