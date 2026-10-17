"""Regression coverage for independently authenticated sensitive approvals."""

import tempfile
import unittest
from pathlib import Path

from app.db import get_connection, init_db
from app.service import AccessService


class ApprovalWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "approval.db"
        init_db(self.path)
        self.conn = get_connection(self.path)
        with self.conn:
            for uid in ("admin_one", "admin_two", "target", "sup_one", "sup_two"):
                self.conn.execute(
                    "INSERT INTO users(id,username,full_name,is_active,created_at) VALUES (?,?,?,?,?)",
                    (uid, uid, uid, 1, "2026-01-01T00:00:00Z"),
                )
            for gid, uid, role in (("ga1", "admin_one", "AccessAdmin"), ("ga2", "admin_two", "AccessAdmin"),
                                   ("gs1", "sup_one", "Supervisor"), ("gs2", "sup_two", "Supervisor")):
                self.conn.execute(
                    "INSERT INTO grants(id,user_id,role_name,scope_json,effect,valid_from,valid_to,recorded_at,created_by) VALUES (?,?,?,?,?,?,?,?,?)",
                    (gid, uid, role, "{}", "allow", "2020-01-01T00:00:00Z", "9999-12-31T00:00:00Z", "2020-01-01T00:00:00Z", "admin_one"),
                )
            self.conn.execute("INSERT INTO jobs(id,client_id,branch,direction,mode,stage,content_json,created_at,updated_at) VALUES ('J1','C1','B1','import','air','Filed','{}','2026-01-01T00:00:00Z','2026-01-01T00:00:00Z')")
        self.service = AccessService(self.conn)

    def tearDown(self):
        self.conn.close()
        self.tmp.cleanup()

    def test_grant_is_inert_until_distinct_admin_approval(self):
        proposal = self.service.propose_grant(user_id="target", role_name="Viewer", scope={}, effect="allow", valid_from=None, valid_to=None, requester_id="admin_one")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM grants WHERE user_id='target'").fetchone()[0], 0)
        with self.assertRaises(PermissionError):
            self.service.approve_grant_proposal(proposal["proposal_id"], "admin_one")
        self.service.approve_grant_proposal(proposal["proposal_id"], "admin_two")
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM grants WHERE user_id='target'").fetchone()[0], 1)
        with self.assertRaises(ValueError):
            self.service.approve_grant_proposal(proposal["proposal_id"], "admin_two")

    def test_filed_transition_requires_distinct_approval_and_one_execution(self):
        request = self.service.request_filed_transition("J1", "cancel", "Customs correction", "sup_one")
        with self.assertRaises(PermissionError):
            self.service.approve_filed_transition(request["request_id"], "sup_one")
        self.assertEqual(self.conn.execute("SELECT stage FROM jobs WHERE id='J1'").fetchone()[0], "Filed")
        self.service.approve_filed_transition(request["request_id"], "sup_two")
        self.service.execute_filed_transition(request["request_id"], "sup_one")
        self.assertEqual(self.conn.execute("SELECT stage FROM jobs WHERE id='J1'").fetchone()[0], "Cancelled")
        with self.assertRaises(ValueError):
            self.service.execute_filed_transition(request["request_id"], "sup_one")

