"""
Seed script for Nagarkot Access Control Service.
Usage:
  python -m app.seed         # Seeds 5 branches, 10 clients, 20 users, ~300 jobs
  python -m app.seed --scale # Seeds 500 users + 200,000 jobs using fast batched inserts
"""

import sys
import os
import json
import sqlite3
import random
import time
from datetime import datetime, timezone
from pathlib import Path

from app.db import init_db, get_connection, DB_PATH
from app.crypto import (
    hash_password,
    hash_api_key,
    compute_job_seal,
    JOB_SEAL_KEY,
    GENESIS_HASH,
    compute_ledger_hash,
    canonical_json,
)
from app.audit import record_ledger_event, build_job_seal_payload
from app.config import LEDGER_HMAC_KEY

BRANCHES = ["Mumbai", "Delhi", "Chennai", "Kolkata", "Ahmedabad"]

CLIENTS = [
    ("C01", "Acme Corporation"),
    ("C02", "Zenith Global Logistics"),
    ("C03", "Tata Logistics & Freight"),
    ("C04", "Reliance Retail Imports"),
    ("C05", "Infosys Hardware Group"),
    ("C06", "Sun Pharma Life Sciences"),
    ("C07", "Bajaj Auto Exports"),
    ("C08", "L&T Heavy Engineering"),
    ("C09", "Mahindra Impex"),
    ("C10", "Adani Ports Client Group"),
]

USERS = [
    ("u_asha", "asha", "Asha Sharma", False, None, "Maker for ALL clients; Checker for C01, C02, C03"),
    ("u_ravi", "ravi", "Ravi Verma", False, None, "Checker for client C03, Mumbai branch, imports only"),
    ("u_meera", "meera", "Meera Nair", False, None, "Supervisor for Mumbai branch (absent; Karan is her delegate)"),
    ("u_karan", "karan", "Karan Joshi", False, None, "Delegate for Meera; active delegation for Mumbai Supervisor"),
    ("u_priya", "priya", "Priya Shah", False, "C02", "ClientViewer for Zenith Global (C02), view-only, redacted"),
    ("u_dev", "dev", "Devendra Patel", False, None, "AccessAdmin (primary security administrator)"),
    ("u_arun", "arun", "Arun Mukherjee", False, None, "AccessAdmin (secondary admin for two-admin approval)"),
    ("u_vikram", "vikram", "Vikram Singh", False, None, "Supervisor for Delhi branch"),
    ("u_ananya", "ananya", "Ananya Iyer", False, None, "Supervisor for Chennai branch"),
    ("u_rajesh", "rajesh", "Rajesh Ghosh", False, None, "Supervisor for Kolkata branch"),
    ("u_sneha", "sneha", "Sneha Mehta", False, None, "Supervisor for Ahmedabad branch"),
    ("u_arjun", "arjun", "Arjun Kapoor", False, None, "Auditor (cross-branch compliance read-only)"),
    ("svc_parser", "svc_parser", "Overnight EDI Parser", True, None, "Service Account (API key, Confirmed stage create/update only)"),
    ("u_suresh", "suresh", "Suresh Kumar", False, None, "Maker for Delhi & Kolkata branches"),
    ("u_deepa", "deepa", "Deepa Reddy", False, None, "Checker for Delhi & Kolkata branches"),
    ("u_manoj", "manoj", "Manoj Tiwari", False, None, "Filer for Mumbai branch"),
    ("u_pooja", "pooja", "Pooja Hegde", False, None, "Filer for Delhi branch"),
    ("u_rahul", "rahul", "Rahul Sen", False, None, "Viewer for Mumbai branch"),
    ("u_rohit", "rohit", "Rohit Deshmukh", False, None, "Maker for Chennai & Ahmedabad branches"),
    ("u_neha", "neha", "Neha Kulkarni", False, None, "Checker for Chennai & Ahmedabad branches"),
]

GRANTS = [
    # Asha: Maker for ALL clients, Checker for C01, C02, C03
    ("G_ASHA_MKR", "u_asha", "Maker", {}, "allow"),
    ("G_ASHA_CHK", "u_asha", "Checker", {"clients": ["C01", "C02", "C03"]}, "allow"),

    # Ravi: Checker for client C03, Mumbai branch, imports only
    ("G_RAVI_CHK", "u_ravi", "Checker", {"clients": ["C03"], "branches": ["Mumbai"], "directions": ["import"]}, "allow"),

    # Meera: Supervisor for Mumbai branch
    ("G_MEERA_SUP", "u_meera", "Supervisor", {"branches": ["Mumbai"]}, "allow"),

    # Priya: ClientViewer for C02
    ("G_PRIYA_VIEW", "u_priya", "ClientViewer", {"clients": ["C02"]}, "allow"),

    # Dev & Arun: AccessAdmin
    ("G_DEV_ADM", "u_dev", "AccessAdmin", {}, "allow"),
    ("G_ARUN_ADM", "u_arun", "AccessAdmin", {}, "allow"),

    # Branch Supervisors
    ("G_VIKRAM_SUP", "u_vikram", "Supervisor", {"branches": ["Delhi"]}, "allow"),
    ("G_ANANYA_SUP", "u_ananya", "Supervisor", {"branches": ["Chennai"]}, "allow"),
    ("G_RAJESH_SUP", "u_rajesh", "Supervisor", {"branches": ["Kolkata"]}, "allow"),
    ("G_SNEHA_SUP", "u_sneha", "Supervisor", {"branches": ["Ahmedabad"]}, "allow"),

    # Auditor
    ("G_ARJUN_AUD", "u_arjun", "Auditor", {}, "allow"),

    # Service Parser
    ("G_SVC_PARSER", "svc_parser", "Service", {}, "allow"),

    # Regional Makers & Checkers & Filers
    ("G_SURESH_MKR", "u_suresh", "Maker", {"branches": ["Delhi", "Kolkata"]}, "allow"),
    ("G_DEEPA_CHK", "u_deepa", "Checker", {"branches": ["Delhi", "Kolkata"]}, "allow"),
    ("G_MANOJ_FIL", "u_manoj", "Filer", {"branches": ["Mumbai"]}, "allow"),
    ("G_POOJA_FIL", "u_pooja", "Filer", {"branches": ["Delhi"]}, "allow"),
    ("G_RAHUL_VIEW", "u_rahul", "Viewer", {"branches": ["Mumbai"]}, "allow"),
    ("G_ROHIT_MKR", "u_rohit", "Maker", {"branches": ["Chennai", "Ahmedabad"]}, "allow"),
    ("G_NEHA_CHK", "u_neha", "Checker", {"branches": ["Chennai", "Ahmedabad"]}, "allow"),
]

def seed_standard(db_path: Path = DB_PATH):
    print(f"Initializing standard seed database at {db_path}...")
    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass
    init_db(db_path)
    conn = get_connection(db_path)

    # Demo secrets are explicit operator input; a fresh database must never
    # silently install reusable passwords or an API key.
    demo_password = os.environ.get("NAGARKOT_DEMO_PASSWORD")
    parser_key = os.environ.get("NAGARKOT_PARSER_API_KEY")
    if not demo_password or not parser_key:
        raise RuntimeError("Set NAGARKOT_DEMO_PASSWORD and NAGARKOT_PARSER_API_KEY before seeding demo identities.")

    # 1. Insert Users
    with conn:
        for uid, uname, name, is_svc, client_id, desc in USERS:
            pwd_hash, salt = hash_password(demo_password) if not is_svc else (None, None)
            api_key_hash = hash_api_key(parser_key) if is_svc else None
            conn.execute(
                """
                INSERT INTO users (id, username, full_name, password_hash, salt, api_key_hash, is_service, client_id, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, '2025-01-01T00:00:00Z')
                """,
                (uid, uname, name, pwd_hash, salt, api_key_hash, 1 if is_svc else 0, client_id),
            )
            record_ledger_event(
                conn, "user_created", "user", uid, "system", {"username": uname, "full_name": name, "description": desc}, timestamp="2025-01-01T00:00:00Z"
            )

    # 2. Insert Grants
    with conn:
        for gid, uid, rname, scope, effect in GRANTS:
            conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by, approved_by)
                VALUES (?, ?, ?, ?, ?, '2025-01-01T00:00:00Z', '9999-12-31T23:59:59Z', '2025-01-01T00:00:00Z', 'u_dev', 'u_arun')
                """,
                (gid, uid, rname, json.dumps(scope), effect),
            )
            record_ledger_event(
                conn, "grant_created", "grant", gid, "u_dev", {"user_id": uid, "role_name": rname, "scope": scope, "effect": effect}, timestamp="2025-01-01T00:00:00Z"
            )

    # 3. Insert Delegation: Meera (absent) delegates to Karan for Mumbai Supervisor
    with conn:
        conn.execute(
            """
            INSERT INTO delegations (id, delegator_id, delegate_id, role_name, scope_json, valid_from, valid_to, reason, status, created_at, created_by)
            VALUES ('DELG_MEERA_KARAN', 'u_meera', 'u_karan', 'Supervisor', '{"branches": ["Mumbai"]}', '2026-01-01T00:00:00Z', '2027-12-31T23:59:59Z', 'Meera on parental leave; Karan covers Mumbai branch', 'active', '2026-01-01T00:00:00Z', 'u_meera')
            """
        )
        record_ledger_event(
            conn, "delegation_created", "delegation", "DELG_MEERA_KARAN", "u_meera", {"delegate_id": "u_karan", "role_name": "Supervisor", "scope": {"branches": ["Mumbai"]}}, timestamp="2026-01-01T00:00:00Z"
        )

    # 4. Insert ~300 Realistic Jobs
    print("Generating ~300 realistic jobs across stages, branches, and clients...")
    stages = ["Confirmed", "Prepared", "Checked", "Filed", "Cancelled", "Reopened"]
    directions = ["import", "export"]
    modes = ["air", "fcl", "lcl"]
    client_ids = [c[0] for c in CLIENTS]

    random.seed(42)  # Deterministic sample seed
    job_rows = []
    filed_jobs_to_seal = []

    for i in range(1, 301):
        jid = f"JOB_{i:04d}"
        client_id = random.choice(client_ids)
        branch = random.choice(BRANCHES)
        direction = random.choice(directions)
        mode = random.choice(modes)
        stage = random.choices(stages, weights=[0.25, 0.25, 0.20, 0.20, 0.05, 0.05])[0]

        prep_by = None
        chk_by = None
        fld_by = None
        assigned_to = None

        # Pin JOB_0051 for demo consistency
        if jid == "JOB_0051":
            client_id = "C01"
            branch = "Ahmedabad"
            direction = "import"
            mode = "air"
            stage = "Prepared"
            prep_by = "u_suresh"
            chk_by = None
            fld_by = None
            assigned_to = "u_suresh"
        else:
            if stage in ("Prepared", "Checked", "Filed"):
                prep_by = random.choice(["u_asha", "u_suresh", "u_rohit"])
                assigned_to = prep_by if stage == "Prepared" else None

            if stage in ("Checked", "Filed"):
                possible_checkers = [u for u in ["u_ravi", "u_deepa", "u_neha", "u_vikram"] if u != prep_by]
                chk_by = random.choice(possible_checkers)

            if stage == "Filed":
                possible_filers = [u for u in ["u_manoj", "u_pooja", "u_ananya"] if u != prep_by]
                fld_by = random.choice(possible_filers)

        content = {
            "invoice_num": f"INV-{client_id}-{1000 + i}",
            "declared_value_inr": random.randint(50_000, 5_000_000),
            "customs_tariff_code": f"{random.randint(1000, 9999)}.{random.randint(10, 90)}",
            "cargo_description": f"{direction.capitalize()} of industrial components via {mode.upper()}",
            "internal_notes": f"Internal broker margin notes for job {jid}",
            "margin": random.randint(1500, 25000),
        }

        job_data = {
            "id": jid,
            "client_id": client_id,
            "branch": branch,
            "direction": direction,
            "mode": mode,
            "stage": stage,
            "prepared_by": prep_by,
            "checked_by": chk_by,
            "filed_by": fld_by,
            "assigned_to": assigned_to,
            "content_json": json.dumps(content),
            "seal_hash": None,
        }

        if stage == "Filed":
            payload = build_job_seal_payload(job_data)
            seal = compute_job_seal(payload, JOB_SEAL_KEY)
            job_data["seal_hash"] = seal

        job_rows.append(job_data)

    # --- After all 300 jobs are built: bulk insert jobs, seals, and audit events ---

    # Bulk insert all jobs into DB
    with conn:
        conn.executemany(
            """
            INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, assigned_to, content_json, seal_hash, created_at, updated_at)
            VALUES (:id, :client_id, :branch, :direction, :mode, :stage, :prepared_by, :checked_by, :filed_by, :assigned_to, :content_json, :seal_hash, '2026-02-01T00:00:00Z', '2026-02-01T00:00:00Z')
            """,
            job_rows,
        )

    # Populate filed_job_seals durable registry for Filed jobs
    filed_seals = []
    for j in job_rows:
        if j["stage"] == "Filed" and j["seal_hash"]:
            payload = build_job_seal_payload(j)
            filed_seals.append((j["id"], j["seal_hash"], canonical_json(payload), j["filed_by"] or "system", "2026-02-01T00:00:00Z"))
    if filed_seals:
        with conn:
            conn.executemany(
                """
                INSERT INTO filed_job_seals (job_id, seal_hash, canonical_payload_json, filed_by, filed_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                filed_seals,
            )

    # Record initial lifecycle events into audit ledger for standard dataset
    with conn:
        for j in job_rows:
            jid = j["id"]
            record_ledger_event(
                conn, "job_created", "job", jid, "svc_parser",
                {"client_id": j["client_id"], "branch": j["branch"], "stage": "Confirmed"},
                timestamp="2026-02-01T00:00:00Z",
            )
            if j["prepared_by"]:
                record_ledger_event(
                    conn, "job_prepare", "job", jid, j["prepared_by"],
                    {"previous_stage": "Confirmed", "new_stage": "Prepared"},
                    timestamp="2026-02-01T02:00:00Z",
                )
            if j["checked_by"]:
                record_ledger_event(
                    conn, "job_check", "job", jid, j["checked_by"],
                    {"previous_stage": "Prepared", "new_stage": "Checked"},
                    timestamp="2026-02-01T04:00:00Z",
                )
            if j["filed_by"]:
                record_ledger_event(
                    conn, "job_file", "job", jid, j["filed_by"],
                    {"previous_stage": "Checked", "new_stage": "Filed", "seal_hash": j["seal_hash"]},
                    timestamp="2026-02-01T06:00:00Z",
                )

        record_ledger_event(
            conn, "seed_completed", "system", "SYSTEM", "system", {"total_jobs": len(job_rows), "total_users": len(USERS)}, timestamp="2026-02-01T08:00:00Z"
        )

    conn.close()
    print(f"[SUCCESS] Standard dataset loaded: 5 branches, 10 clients, 20 users, {len(job_rows)} jobs.")

def seed_scale(db_path: Path = DB_PATH):
    print("=" * 70)
    print("SCALE SEED: Generating 500 users + 200,000 jobs in SQLite WAL mode...")
    print("=" * 70)
    t0 = time.time()

    demo_password = os.environ.get("NAGARKOT_DEMO_PASSWORD")
    parser_key = os.environ.get("NAGARKOT_PARSER_API_KEY")
    if not demo_password or not parser_key:
        raise RuntimeError("Set NAGARKOT_DEMO_PASSWORD and NAGARKOT_PARSER_API_KEY before seeding demo identities.")

    if db_path.exists():
        try:
            db_path.unlink()
        except Exception:
            pass

    init_db(db_path)
    conn = get_connection(db_path)

    # 1. First seed standard baseline users and grants
    print("1/3 Seeding baseline users and grants...")
    with conn:
        for uid, uname, name, is_svc, client_id, desc in USERS:
            pwd_hash, salt = hash_password(demo_password) if not is_svc else (None, None)
            api_key_hash = hash_api_key(parser_key) if is_svc else None
            conn.execute(
                """
                INSERT INTO users (id, username, full_name, password_hash, salt, api_key_hash, is_service, client_id, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, '2025-01-01T00:00:00Z')
                """,
                (uid, uname, name, pwd_hash, salt, api_key_hash, 1 if is_svc else 0, client_id),
            )
        for gid, uid, rname, scope, effect in GRANTS:
            conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by, approved_by)
                VALUES (?, ?, ?, ?, ?, '2025-01-01T00:00:00Z', '9999-12-31T23:59:59Z', '2025-01-01T00:00:00Z', 'u_dev', 'u_arun')
                """,
                (gid, uid, rname, json.dumps(scope), effect),
            )
        conn.execute(
            """
            INSERT INTO delegations (id, delegator_id, delegate_id, role_name, scope_json, valid_from, valid_to, reason, status, created_at, created_by)
            VALUES ('DELG_MEERA_KARAN', 'u_meera', 'u_karan', 'Supervisor', '{"branches": ["Mumbai"]}', '2026-01-01T00:00:00Z', '2027-12-31T23:59:59Z', 'Meera leave', 'active', '2026-01-01T00:00:00Z', 'u_meera')
            """
        )

    # 2. Generate remaining up to 500 users
    print("2/3 Generating 500 users with grants across branches...")
    user_batch = []
    grant_batch = []
    roles_pool = ["Maker", "Checker", "Filer", "Supervisor", "Viewer"]

    for i in range(21, 501):
        uid = f"user_{i:04d}"
        uname = f"staff_{i:04d}"
        fname = f"Staff Member {i}"
        branch = random.choice(BRANCHES)
        client = random.choice([c[0] for c in CLIENTS])
        role = random.choice(roles_pool)
        user_batch.append((uid, uname, fname, 0, None, 1, "2025-01-01T00:00:00Z"))
        scope = {"branches": [branch]} if random.random() < 0.8 else {"clients": [client]}
        grant_batch.append((
            f"G_SCALE_{i:04d}",
            uid,
            role,
            json.dumps(scope),
            "allow",
            "2025-01-01T00:00:00Z",
            "9999-12-31T23:59:59Z",
            "2025-01-01T00:00:00Z",
            "u_dev",
            "u_arun",
        ))

    with conn:
        conn.executemany(
            """
            INSERT INTO users (id, username, full_name, is_service, client_id, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            user_batch,
        )
        conn.executemany(
            """
            INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, created_by, approved_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            grant_batch,
        )

    # 3. Generate 200,000 jobs in batches of 10,000
    print("3/3 Generating 200,000 jobs (in 20 batched transactions)...")
    stages = ["Confirmed", "Prepared", "Checked", "Filed", "Cancelled", "Reopened"]
    stage_weights = [0.30, 0.25, 0.20, 0.20, 0.03, 0.02]
    directions = ["import", "export"]
    modes = ["air", "fcl", "lcl"]
    client_ids = [c[0] for c in CLIENTS]
    maker_ids = [u[0] for u in user_batch[:100]] + ["u_asha", "u_suresh", "u_rohit"]
    checker_ids = [u[0] for u in user_batch[100:200]] + ["u_ravi", "u_deepa", "u_neha"]
    filer_ids = [u[0] for u in user_batch[200:300]] + ["u_manoj", "u_pooja"]

    TOTAL_JOBS = 200_000
    BATCH_SIZE = 10_000

    for batch_idx in range(0, TOTAL_JOBS, BATCH_SIZE):
        t_batch_start = time.time()
        batch_jobs = []
        for i in range(batch_idx + 1, batch_idx + BATCH_SIZE + 1):
            jid = f"JOB_{i:07d}"
            cid = random.choice(client_ids)
            br = random.choice(BRANCHES)
            d = random.choice(directions)
            m = random.choice(modes)
            st = random.choices(stages, weights=stage_weights)[0]

            p_by = None
            c_by = None
            f_by = None
            asgn = None

            if st in ("Prepared", "Checked", "Filed"):
                p_by = random.choice(maker_ids)
                asgn = p_by if st == "Prepared" else None
            if st in ("Checked", "Filed"):
                c_by = random.choice(checker_ids)
            if st == "Filed":
                f_by = random.choice(filer_ids)

            seal = None
            if st == "Filed":
                # Compute lightweight deterministic seal
                seal = compute_job_seal({
                    "job_id": jid, "client_id": cid, "branch": br, "direction": d, "mode": m,
                    "stage": "Filed", "prepared_by": p_by, "checked_by": c_by, "filed_by": f_by,
                    "content": {"val": 100000}
                }, JOB_SEAL_KEY)

            batch_jobs.append((
                jid, cid, br, d, m, st, p_by, c_by, f_by, asgn,
                '{"invoice_val": 100000}', seal, "2026-03-01T00:00:00Z", "2026-03-01T00:00:00Z"
            ))

        with conn:
            conn.executemany(
                """
                INSERT INTO jobs (id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, assigned_to, content_json, seal_hash, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                batch_jobs,
            )
            scale_filed = [
                (bj[0], bj[11], canonical_json({
                    "job_id": bj[0], "client_id": bj[1], "branch": bj[2], "direction": bj[3], "mode": bj[4],
                    "stage": "Filed", "prepared_by": bj[6], "checked_by": bj[7], "filed_by": bj[8],
                    "content": {"val": 100000}
                }), bj[8] or "system", "2026-03-01T00:00:00Z")
                for bj in batch_jobs if bj[5] == "Filed" and bj[11]
            ]
            if scale_filed:
                conn.executemany(
                    """
                    INSERT INTO filed_job_seals (job_id, seal_hash, canonical_payload_json, filed_by, filed_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    scale_filed,
                )
        elapsed_batch = time.time() - t_batch_start
        print(f"  Inserted batch {batch_idx + BATCH_SIZE:,} / {TOTAL_JOBS:,} ({elapsed_batch:.2f}s)")

    # Record ledger event
    with conn:
        record_ledger_event(
            conn, "scale_seed_completed", "system", "SYSTEM", "system", {"total_jobs": TOTAL_JOBS, "total_users": 500}
        )

    conn.close()
    total_elapsed = time.time() - t0
    print("=" * 70)
    print(f"[SUCCESS] Scale seed complete: 500 users + 200,000 jobs created in {total_elapsed:.1f} seconds!")
    print("=" * 70)

def main():
    if "--scale" in sys.argv:
        seed_scale()
    else:
        seed_standard()

if __name__ == "__main__":
    main()
