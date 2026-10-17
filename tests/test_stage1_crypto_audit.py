"""
Unit tests for Stage 1: Cryptographic primitives, DB init, WAL mode, HMAC ledger chaining,
tamper detection, job seal verification, and probe detection.
"""

import unittest
import sqlite3
import json
import tempfile
import time
from pathlib import Path

from app.db import init_db, get_connection, DEFAULT_ROLES
from app.crypto import (
    hash_password,
    verify_password,
    hash_api_key,
    canonical_json,
    compute_ledger_hash,
    compute_job_seal,
    sign_decision_receipt,
    verify_receipt_signature,
    GENESIS_HASH,
)
from app.audit import (
    record_ledger_event,
    verify_ledger,
    build_job_seal_payload,
    verify_job_seals,
    record_security_denial,
    record_filed_job_tamper_alert,
)
from app.config import JOB_SEAL_KEY

class TestStage1CryptoAndAudit(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        init_db(self.db_path)
        self.conn = get_connection(self.db_path)

    def tearDown(self):
        self.conn.close()
        self.temp_dir.cleanup()

    def test_database_wal_mode_and_default_roles(self):
        cur = self.conn.execute("PRAGMA journal_mode")
        mode = cur.fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

        cur = self.conn.execute("SELECT name FROM roles ORDER BY name")
        role_names = [r["name"] for r in cur.fetchall()]
        expected_roles = sorted([r["name"] for r in DEFAULT_ROLES])
        self.assertEqual(role_names, expected_roles)

    def test_password_hashing_and_verification(self):
        pwd = "SuperSecretCustomsPass#123"
        hashed, salt = hash_password(pwd)
        self.assertTrue(verify_password(pwd, hashed, salt))
        self.assertFalse(verify_password("WrongPass", hashed, salt))

    def test_receipt_signature(self):
        receipt = {
            "decision": "ALLOW",
            "actor_id": "U01",
            "job_id": "J100",
            "action": "check",
            "policy_version": 1,
            "rule": "matching_grant",
        }
        sig = sign_decision_receipt(receipt)
        self.assertTrue(verify_receipt_signature(receipt, sig))
        
        # Tampered receipt
        tampered_receipt = dict(receipt)
        tampered_receipt["decision"] = "DENY"
        self.assertFalse(verify_receipt_signature(tampered_receipt, sig))

    def test_audit_ledger_chaining_and_tamper_detection(self):
        # Insert 3 events
        with self.conn:
            seq1 = record_ledger_event(
                self.conn, "user_created", "user", "U01", "admin", {"name": "Asha"}
            )
            seq2 = record_ledger_event(
                self.conn, "grant_created", "grant", "G01", "admin", {"role": "Maker"}
            )
            seq3 = record_ledger_event(
                self.conn, "job_created", "job", "J01", "U01", {"branch": "Mumbai"}
            )

        valid, broken_seq, msg = verify_ledger(self.conn)
        self.assertTrue(valid)
        self.assertIsNone(broken_seq)

        # Tamper directly with the details of row 2
        with self.conn:
            self.conn.execute(
                "UPDATE audit_ledger SET details_json = ? WHERE seq = ?",
                (json.dumps({"role": "Supervisor"}), seq2),
            )

        valid, broken_seq, msg = verify_ledger(self.conn)
        self.assertFalse(valid)
        self.assertEqual(broken_seq, seq2)
        self.assertIn("Tampered event data at seq 2", msg)

    def test_job_seal_generation_and_tamper_detection(self):
        # Insert a Filed job with legitimate seal
        job_data = {
            "id": "J_TEST_01",
            "client_id": "C01",
            "branch": "Mumbai",
            "direction": "import",
            "mode": "air",
            "stage": "Filed",
            "prepared_by": "U_MAKER",
            "checked_by": "U_CHECKER",
            "filed_by": "U_FILER",
            "content_json": json.dumps({"invoice_val": 50000, "hs_code": "8471.30"}),
        }
        # Insert dummy users to satisfy foreign keys
        with self.conn:
            for uid in ["U_MAKER", "U_CHECKER", "U_FILER"]:
                self.conn.execute(
                    "INSERT INTO users (id, username, full_name, created_at) VALUES (?, ?, ?, datetime('now'))",
                    (uid, uid.lower(), uid)
                )

        payload = build_job_seal_payload(job_data)
        seal = compute_job_seal(payload, JOB_SEAL_KEY)

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, content_json, seal_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                """,
                (
                    job_data["id"],
                    job_data["client_id"],
                    job_data["branch"],
                    job_data["direction"],
                    job_data["mode"],
                    job_data["stage"],
                    job_data["prepared_by"],
                    job_data["checked_by"],
                    job_data["filed_by"],
                    job_data["content_json"],
                    seal,
                ),
            )

        # Initial verification should report 0 tampered jobs
        tampered = verify_job_seals(self.conn)
        self.assertEqual(len(tampered), 0)

        # Direct DB tamper: modify invoice_val directly in SQLite
        with self.conn:
            self.conn.execute(
                "UPDATE jobs SET content_json = ? WHERE id = ?",
                (json.dumps({"invoice_val": 999999, "hs_code": "8471.30"}), "J_TEST_01"),
            )

        tampered = verify_job_seals(self.conn)
        self.assertEqual(len(tampered), 1)
        self.assertEqual(tampered[0]["job_id"], "J_TEST_01")
        self.assertIn("HMAC seal mismatch", tampered[0]["reason"])

    def test_probe_attack_detection_mitre(self):
        # 5 denials within window triggers an ANOMALY event
        actor = "malicious_user"
        now = time.time()
        with self.conn:
            for i in range(4):
                anomaly_id = record_security_denial(
                    self.conn, actor, "prepare", f"J{i}", "Denied by scope", now_epoch=now + i
                )
                self.assertIsNone(anomaly_id)

            # 5th denial triggers anomaly event
            anomaly_id = record_security_denial(
                self.conn, actor, "prepare", "J5", "Denied by scope", now_epoch=now + 5
            )
            self.assertIsNotNone(anomaly_id)

        # Check audit ledger has the anomaly event
        cur = self.conn.execute("SELECT * FROM audit_ledger WHERE event_type = 'anomaly'")
        row = cur.fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row["actor_id"], actor)
        details = json.loads(row["details_json"])
        self.assertIn("T1078", details["mitre_attack"])
        self.assertIn("T1087", details["mitre_attack"])

    def test_filed_job_tamper_alert(self):
        with self.conn:
            seq = record_filed_job_tamper_alert(
                self.conn, "hacker", "update", "J_FILED_01", {"attempted_changes": {"val": 1}}
            )
        cur = self.conn.execute("SELECT * FROM audit_ledger WHERE seq = ?", (seq,))
        row = cur.fetchone()
        self.assertEqual(row["event_type"], "alert")
        self.assertEqual(row["actor_id"], "hacker")

if __name__ == "__main__":
    unittest.main()
