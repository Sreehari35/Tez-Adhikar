"""
Command Line Interface (CLI) for Nagarkot Access Control Service.
Standard library only: argparse, json, sys.
"""

import argparse
import json
import sys
from typing import Optional

from app.db import get_connection, init_db
from app.audit import verify_ledger, verify_job_seals
from app.service import AccessService
from app.server import run_server

def cmd_verify(args):
    conn = get_connection()
    try:
        valid, broken_seq, msg = verify_ledger(conn)
        if valid:
            print(f"[OK] Audit Ledger Integrity Verified: {msg}")
            sys.exit(0)
        else:
            print(f"[TAMPER DETECTED] Broken chain at sequence #{broken_seq}")
            print(f"Details: {msg}")
            sys.exit(1)
    finally:
        conn.close()

def cmd_verify_jobs(args):
    conn = get_connection()
    try:
        tampered = verify_job_seals(conn)
        if not tampered:
            print("[OK] All Filed jobs match their cryptographic HMAC seals. Zero unauthorized modifications detected.")
            sys.exit(0)
        else:
            print(f"[ALERT] {len(tampered)} Filed job(s) have been altered directly in the database:")
            for item in tampered:
                print(f"  - Job ID: {item['job_id']}")
                print(f"    Reason: {item['reason']}")
                print(f"    Stored Seal:   {item['stored_seal']}")
                print(f"    Expected Seal: {item['expected_seal']}")
            sys.exit(1)
    finally:
        conn.close()

def cmd_who_could_change(args):
    conn = get_connection()
    try:
        service = AccessService(conn)
        res = service.who_could_change(job_id=args.job, at_timestamp=args.at)
        print("=" * 70)
        print(f"FORENSIC TIME MACHINE: Job {res['job_id']} as of {args.at}")
        print("=" * 70)
        print(f"Job Baseline Then: Stage={res['job_state_then']['stage']}, Branch={res['job_state_then']['branch']}, Client={res['job_state_then']['client_id']}, PreparedBy={res['job_state_then']['prepared_by']}")
        print("\n--- Authorized Personnel At That Time ---")
        if not res["who_could_act"]:
            print("  (None)")
        else:
            for item in res["who_could_act"]:
                print(f"  * User: {item['username']} ({item['user_id']}) -> Action: '{item['authorized_action']}' via rule: {item['rule']}")

        print("\n--- Actual Audit Trail On This Job ---")
        if not res["actual_history_events"]:
            print("  (No recorded events for this job)")
        else:
            for ev in res["actual_history_events"]:
                print(f"  [Seq #{ev['seq']} @ {ev['timestamp']}] Event: {ev['event_type']} by {ev['actor_id']}")
        print("=" * 70)
    finally:
        conn.close()

def cmd_explain(args):
    conn = get_connection()
    try:
        service = AccessService(conn)
        res = service.explain(
            user_a_id=args.user,
            user_b_id=args.other,
            action=args.action,
            job_id=args.job,
        )
        print("=" * 70)
        print(f"DECISION EXPLAINER: Action '{args.action}' on Job {args.job}")
        print("=" * 70)
        js = res["job_summary"]
        print(f"Job: Client={js['client_id']}, Branch={js['branch']}, Direction={js['direction']}, Mode={js['mode']}, Stage={js['stage']}, PreparedBy={js['prepared_by']}")
        print("-" * 70)
        print(f"User A ({args.user}):")
        print(f"  Decision: {res['user_a']['decision']} ({res['user_a']['code']})")
        print(f"  Rule:     {res['user_a']['rule']}")
        print(f"  Grants:   {res['user_a']['matched_grant_ids']}")
        print("-" * 70)
        print(f"User B ({args.other}):")
        print(f"  Decision: {res['user_b']['decision']} ({res['user_b']['code']})")
        print(f"  Rule:     {res['user_b']['rule']}")
        print(f"  Grants:   {res['user_b']['matched_grant_ids']}")
        print("-" * 70)
        print(f"Summary: {res['comparison_summary']}")
        print("=" * 70)
    finally:
        conn.close()

def cmd_simulate_grant(args):
    conn = get_connection()
    try:
        service = AccessService(conn)
        scope = json.loads(args.scope) if args.scope else {}
        res = service.simulate_grant(
            grantor_id=args.grantor,
            user_id=args.user,
            role_name=args.role,
            scope=scope,
        )
        print("=" * 70)
        print("BLAST-RADIUS DRY-RUN SIMULATION (NO CHANGES APPLIED)")
        print("=" * 70)
        print(f"Proposed Grant: User={args.user}, Role={args.role}, Scope={scope}")
        print(f"Grantor:        {args.grantor}")
        print(f"Raises Grantor's Own Privilege: {res['raises_grantor_own_privilege']}")
        print(f"Jobs Gained Count:              {res['jobs_gained_count']}")
        print(f"SoD Conflicts Created Count:    {res['sod_conflicts_created_count']}")
        if res["sod_conflicts_created_count"] > 0:
            print("  [!] WARNING: Target user has previously prepared jobs in this scope.")
            print("      Separation of Duties will block them from approving/filing those jobs.")
        print("=" * 70)
    finally:
        conn.close()

def cmd_serve(args):
    run_server(host=args.host, port=args.port)

def main():
    parser = argparse.ArgumentParser(description="Nagarkot Access Control Service CLI")
    subparsers = parser.add_subparsers(dest="subcommand", required=True)

    # verify
    sub_verify = subparsers.add_parser("verify", help="Verify cryptographic audit ledger integrity")
    sub_verify.set_defaults(func=cmd_verify)

    # verify-jobs
    sub_verify_jobs = subparsers.add_parser("verify-jobs", help="Verify cryptographic HMAC seals on all Filed jobs")
    sub_verify_jobs.set_defaults(func=cmd_verify_jobs)

    # who-could-change
    sub_time = subparsers.add_parser("who-could-change", help="Forensic Time Machine: historical grant replay")
    sub_time.add_argument("--job", required=True, help="Job ID")
    sub_time.add_argument("--at", required=True, help="ISO-8601 timestamp (e.g. 2026-03-01T00:00:00Z)")
    sub_time.set_defaults(func=cmd_who_could_change)

    # explain
    sub_explain = subparsers.add_parser("explain", help="Side-by-side decision explainer")
    sub_explain.add_argument("--user", required=True, help="First user ID")
    sub_explain.add_argument("--other", required=True, help="Second user ID")
    sub_explain.add_argument("--action", required=True, help="Action (e.g. check, prepare, file)")
    sub_explain.add_argument("--job", required=True, help="Job ID")
    sub_explain.set_defaults(func=cmd_explain)

    # simulate-grant
    sub_sim = subparsers.add_parser("simulate-grant", help="Blast-radius dry run for proposed grant")
    sub_sim.add_argument("--grantor", required=True, help="Admin proposing the grant")
    sub_sim.add_argument("--user", required=True, help="Target user receiving role")
    sub_sim.add_argument("--role", required=True, help="Role name")
    sub_sim.add_argument("--scope", default="{}", help="Scope JSON (e.g. '{\"branches\": [\"Mumbai\"]}')")
    sub_sim.set_defaults(func=cmd_simulate_grant)

    # serve
    sub_serve = subparsers.add_parser("serve", help="Run HTTP server")
    sub_serve.add_argument("--host", default="127.0.0.1", help="Host interface")
    sub_serve.add_argument("--port", type=int, default=8000, help="Port")
    sub_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)

if __name__ == "__main__":
    main()
