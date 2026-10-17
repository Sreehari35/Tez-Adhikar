"""
Unit tests for Stage 3: Admin self-escalation protection, delegation boundaries,
no-chaining enforcement, responsibility change pool reassignment,
blast-radius simulation, forensic time machine, and breakglass.
"""

import unittest
import sqlite3
import json
import tempfile
from pathlib import Path
from datetime import datetime, timezone, timedelta

from app.db import init_db, get_connection
from app.service import AccessService
from app.audit import record_ledger_event

class TestStage3GrantsAndDelegation(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test3.db"
        init_db(self.db_path)
        self.conn = get_connection(self.db_path)
        self.service = AccessService(self.conn)
        self._seed_baseline()

    def tearDown(self):
        if hasattr(self, "conn") and self.conn:
            self.conn.close()
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def _seed_baseline(self):
        with self.conn:
            # Admins
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('admin_dev', 'dev', 'Dev Admin', datetime('now'))")
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('admin_other', 'other_admin', 'Other Admin', datetime('now'))")
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('u_meera', 'meera', 'Meera', datetime('now'))")
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('u_karan', 'karan', 'Karan', datetime('now'))")
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('u_third', 'third', 'Third User', datetime('now'))")
            self.conn.execute("INSERT INTO users (id, username, full_name, created_at) VALUES ('u_maker', 'maker1', 'Maker 1', datetime('now'))")

            # Grants
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by)
                VALUES ('G_DEV_ADM', 'admin_dev', 'AccessAdmin', '{}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'system'),
                       ('G_OTH_ADM', 'admin_other', 'AccessAdmin', '{}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'system'),
                       ('G_MEERA_SUP', 'u_meera', 'Supervisor', '{"branches": ["Mumbai"]}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'system'),
                       ('G_MAKER1', 'u_maker', 'Maker', '{"branches": ["Mumbai"]}', 'allow', '2020-01-01', '9999-12-31', '2020-01-01T00:00:00Z', 'system')
                """
            )

            # Job claimed by u_maker
            self.conn.execute(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, assigned_to, created_at, updated_at)
                VALUES ('J_CLAIMED_01', 'C01', 'Mumbai', 'import', 'air', 'Prepared', 'u_maker', 'u_maker', datetime('now'), datetime('now'))
                """
            )

    def test_admin_self_escalation_blocked(self):
        # Admin Dev tries to grant himself Supervisor role -> MUST FAIL
        with self.assertRaises(PermissionError) as ctx:
            self.service.create_grant(
                user_id="admin_dev",
                role_name="Supervisor",
                scope={},
                created_by="admin_dev",
            )
        self.assertIn("Self-escalation blocked", str(ctx.exception))

    def test_admin_modifying_another_admin_requires_distinct_approver(self):
        # Dev tries to grant Supervisor to another admin (Other Admin) without second approver -> MUST FAIL
        with self.assertRaises(PermissionError) as ctx:
            self.service.create_grant(
                user_id="admin_other",
                role_name="Supervisor",
                scope={},
                created_by="admin_dev",
                approved_by=None,
            )
        self.assertIn("Two-admin rule violated", str(ctx.exception))

    def test_delegation_scope_limit_and_chaining_blocked(self):
        # Meera delegates Supervisor for Mumbai to Karan -> OK
        delg = self.service.create_delegation(
            delegator_id="u_meera",
            delegate_id="u_karan",
            role_name="Supervisor",
            scope={"branches": ["Mumbai"]},
            reason="Medical leave",
        )
        self.assertEqual(delg["status"], "active")

        # Meera tries to delegate Delhi branch (outside her Mumbai scope) -> MUST FAIL
        with self.assertRaises(PermissionError) as ctx:
            self.service.create_delegation(
                delegator_id="u_meera",
                delegate_id="u_third",
                role_name="Supervisor",
                scope={"branches": ["Delhi"]},
                reason="Coverage",
            )
        self.assertIn("exceeds delegator's permitted", str(ctx.exception))

        # Chaining blocked: Karan (who is a delegate) tries to delegate to Third User -> MUST FAIL
        with self.assertRaises(PermissionError) as ctx:
            self.service.create_delegation(
                delegator_id="u_karan",
                delegate_id="u_third",
                role_name="Supervisor",
                scope={"branches": ["Mumbai"]},
                reason="Sub-delegating",
            )
        self.assertIn("Delegation chaining is strictly prohibited", str(ctx.exception))

    def test_responsibility_change_releases_jobs_and_preserves_attribution(self):
        # Initial check: job is claimed by u_maker, prepared_by is u_maker
        job_before = self.conn.execute("SELECT * FROM jobs WHERE id = 'J_CLAIMED_01'").fetchone()
        self.assertEqual(job_before["assigned_to"], "u_maker")
        self.assertEqual(job_before["prepared_by"], "u_maker")

        # Revoke u_maker's grant
        res = self.service.revoke_grant(grant_id="G_MAKER1", actor_id="admin_dev")
        self.assertEqual(res["status"], "closed")
        self.assertEqual(res["released_jobs_count"], 1)

        # Job must be released to pool (assigned_to is NULL), but prepared_by STAYS u_maker!
        job_after = self.conn.execute("SELECT * FROM jobs WHERE id = 'J_CLAIMED_01'").fetchone()
        self.assertIsNone(job_after["assigned_to"])
        self.assertEqual(job_after["prepared_by"], "u_maker")

        # Check ledger has reassigned event
        cur = self.conn.execute("SELECT * FROM audit_ledger WHERE event_type = 'reassigned'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["entity_id"], "J_CLAIMED_01")
        details = json.loads(row["details_json"])
        self.assertEqual(details["previous_assignee"], "u_maker")

    def test_blast_radius_simulator_dry_run(self):
        # Dry run grant for u_maker giving Checker role
        sim = self.service.simulate_grant(
            grantor_id="admin_dev",
            user_id="u_maker",
            role_name="Checker",
            scope={"branches": ["Mumbai"]},
        )
        self.assertEqual(sim["status"], "dry_run_complete")
        self.assertFalse(sim["raises_grantor_own_privilege"])
        # Since u_maker prepared J_CLAIMED_01, granting Checker produces an SoD conflict!
        self.assertGreaterEqual(sim["sod_conflicts_created_count"], 1)

        # Check DB: no grant was created
        cur = self.conn.execute("SELECT COUNT(*) as cnt FROM grants WHERE user_id = 'u_maker' AND role_name = 'Checker'")
        self.assertEqual(cur.fetchone()["cnt"], 0)

    def test_forensic_time_machine(self):
        # Insert audit ledger event for J_CLAIMED_01
        with self.conn:
            record_ledger_event(
                self.conn,
                event_type="job_prepared",
                entity_type="job",
                entity_id="J_CLAIMED_01",
                actor_id="u_maker",
                details={"step": "checklist_verified"},
                timestamp="2026-01-01T10:00:00Z",
            )

        replay = self.service.who_could_change(job_id="J_CLAIMED_01", at_timestamp="2026-01-01T12:00:00Z")
        self.assertEqual(replay["job_id"], "J_CLAIMED_01")
        self.assertGreaterEqual(len(replay["who_could_act"]), 1)
        self.assertGreaterEqual(len(replay["actual_history_events"]), 1)
        self.assertEqual(replay["actual_history_events"][0]["actor_id"], "u_maker")

    def test_breakglass_and_ratification(self):
        # Dev invokes breakglass
        bg = self.service.trigger_breakglass(admin_id="admin_dev", reason="Critical outage on customs gateway")
        self.assertEqual(bg["status"], "active")
        bg_id = bg["breakglass_id"]

        # Alert logged in ledger
        cur = self.conn.execute("SELECT * FROM audit_ledger WHERE event_type = 'alert' AND entity_id = ?", (bg_id,))
        self.assertIsNotNone(cur.fetchone())

        # Self-ratification must fail
        with self.assertRaises(PermissionError):
            self.service.ratify_breakglass(breakglass_id=bg_id, ratifier_id="admin_dev")

        # Distinct admin ratifies
        rat = self.service.ratify_breakglass(breakglass_id=bg_id, ratifier_id="admin_other")
        self.assertEqual(rat["status"], "ratified")

if __name__ == "__main__":
    unittest.main()
