"""
Cryptographic Audit Ledger, Job Seal Verification, and Probe/Alert Detection.
Standard library only: sqlite3, time, datetime, json.
"""

import time
import json
import hmac
import sqlite3
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from app.crypto import (
    canonical_json,
    compute_ledger_hash,
    compute_job_seal,
    GENESIS_HASH,
)
from app.config import (
    LEDGER_HMAC_KEY,
    JOB_SEAL_KEY,
    PROBE_THRESHOLD_COUNT,
    PROBE_WINDOW_SECONDS,
)

def record_ledger_event(
    conn: sqlite3.Connection,
    event_type: str,
    entity_type: str,
    entity_id: str,
    actor_id: str,
    details: Dict[str, Any],
    timestamp: Optional[str] = None,
) -> int:
    """
    Append an immutable event to the audit ledger with cryptographic HMAC chaining.
    """
    ts = timestamp or datetime.now(timezone.utc).isoformat()
    
    # Fetch previous row hash
    cur = conn.execute(
        "SELECT row_hash FROM audit_ledger ORDER BY seq DESC LIMIT 1"
    )
    row = cur.fetchone()
    prev_hash = row["row_hash"] if row else GENESIS_HASH
    
    canonical_event = {
        "event_type": event_type,
        "entity_type": entity_type,
        "entity_id": str(entity_id),
        "actor_id": str(actor_id),
        "timestamp": ts,
        "details": details,
    }
    canonical_event_str = canonical_json(canonical_event)
    row_hash = compute_ledger_hash(prev_hash, canonical_event_str, LEDGER_HMAC_KEY)
    
    cur = conn.execute(
        """
        INSERT INTO audit_ledger (prev_hash, event_type, entity_type, entity_id, actor_id, timestamp, details_json, row_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (prev_hash, event_type, entity_type, str(entity_id), str(actor_id), ts, canonical_json(details), row_hash),
    )
    return cur.lastrowid

def verify_ledger(conn: sqlite3.Connection) -> Tuple[bool, Optional[int], str]:
    """
    Verify entire audit ledger chain.
    Returns: (is_valid, first_broken_seq_or_none, description)
    """
    cur = conn.execute(
        "SELECT seq, prev_hash, event_type, entity_type, entity_id, actor_id, timestamp, details_json, row_hash FROM audit_ledger ORDER BY seq ASC"
    )
    rows = cur.fetchall()
    if not rows:
        return True, None, "Ledger is empty"
    
    expected_prev_hash = GENESIS_HASH
    for r in rows:
        seq = r["seq"]
        actual_prev_hash = r["prev_hash"]
        actual_row_hash = r["row_hash"]
        
        # Check chaining consistency
        if actual_prev_hash != expected_prev_hash:
            return False, seq, f"Broken chain at seq {seq}: expected prev_hash {expected_prev_hash}, got {actual_prev_hash}"
        
        # Parse details
        try:
            details_obj = json.loads(r["details_json"])
        except Exception:
            details_obj = r["details_json"]
            
        canonical_event = {
            "event_type": r["event_type"],
            "entity_type": r["entity_type"],
            "entity_id": str(r["entity_id"]),
            "actor_id": str(r["actor_id"]),
            "timestamp": r["timestamp"],
            "details": details_obj,
        }
        recomputed_hash = compute_ledger_hash(actual_prev_hash, canonical_json(canonical_event), LEDGER_HMAC_KEY)
        if recomputed_hash != actual_row_hash:
            return False, seq, f"Tampered event data at seq {seq}: recomputed {recomputed_hash} != stored {actual_row_hash}"
        
        expected_prev_hash = actual_row_hash

    return True, None, f"All {len(rows)} ledger entries verified successfully"

def build_job_seal_payload(job: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    """
    Build canonical representation of a Filed job for cryptographic sealing.
    """
    content = job["content_json"]
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except Exception:
            pass
            
    return {
        "job_id": job["id"],
        "client_id": job["client_id"],
        "branch": job["branch"],
        "direction": job["direction"],
        "mode": job["mode"],
        "stage": "Filed",
        "prepared_by": job["prepared_by"],
        "checked_by": job["checked_by"],
        "filed_by": job["filed_by"],
        "content": content,
    }

def verify_job_seals(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """
    Scan filed declarations and verify HMAC job seals against durable filed_job_seals registry.
    Detects:
    1. Direct tampering with content, client, branch, direction, mode, or workflow participants.
    2. Unauthorized stage changes (e.g. changing Filed -> Prepared directly in SQLite without two-person approval).
    3. Missing seals on Filed jobs.
    4. Mismatch between job seal and durable filed seal registry.
    """
    tampered_jobs = []
    
    # Check 1: All records in filed_job_seals (durable registry of every job that was ever legitimately filed)
    # Ensure that the job exists and hasn't been maliciously altered
    sealed_cur = conn.execute("SELECT * FROM filed_job_seals")
    for srow in sealed_cur.fetchall():
        jid = srow["job_id"]
        canonical_payload_str = srow["canonical_payload_json"]
        recorded_seal = srow["seal_hash"]
        
        # Verify recorded seal against canonical payload
        try:
            canon_obj = json.loads(canonical_payload_str)
        except Exception:
            canon_obj = canonical_payload_str
            
        expected_seal = compute_job_seal(canon_obj, JOB_SEAL_KEY)
        if not hmac.compare_digest(recorded_seal, expected_seal):
            tampered_jobs.append({
                "job_id": jid,
                "reason": "Filed seal registry corrupted or seal mismatch",
                "stored_seal": recorded_seal,
                "expected_seal": expected_seal,
            })
            continue
            
        # Check current job in jobs table
        jcur = conn.execute("SELECT * FROM jobs WHERE id = ?", (jid,))
        jrow = jcur.fetchone()
        if not jrow:
            tampered_jobs.append({
                "job_id": jid,
                "reason": "Filed job record deleted from database",
                "stored_seal": recorded_seal,
                "expected_seal": None,
            })
            continue

        # If job is in 'Filed' stage, verify its live content matches the seal
        if jrow["stage"] == "Filed":
            live_payload = build_job_seal_payload(jrow)
            live_seal = compute_job_seal(live_payload, JOB_SEAL_KEY)
            if not hmac.compare_digest(live_seal, recorded_seal):
                tampered_jobs.append({
                    "job_id": jid,
                    "reason": "Filed job content modified directly in DB",
                    "stored_seal": jrow["seal_hash"],
                    "expected_seal": live_seal,
                })
        else:
            # If job is NOT in 'Filed' stage, check if it was legitimately reopened or cancelled via approved two-person transition
            # Check audit ledger for legitimate authorized reopening/cancellation
            app_cur = conn.execute(
                "SELECT event_type FROM audit_ledger WHERE entity_id = ? AND event_type IN ('job_reopen', 'job_cancel') ORDER BY seq DESC LIMIT 1",
                (jid,)
            )
            legit_event = app_cur.fetchone()
            if not legit_event:
                tampered_jobs.append({
                    "job_id": jid,
                    "reason": f"Unauthorized stage modification directly in DB: stage is '{jrow['stage']}' without authorized transition",
                    "stored_seal": jrow["seal_hash"],
                    "expected_seal": recorded_seal,
                })

    # Check 2: Jobs whose current stage is 'Filed'
    cur = conn.execute(
        "SELECT id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, content_json, seal_hash FROM jobs WHERE stage = 'Filed'"
    )
    for r in cur.fetchall():
        stored_seal = r["seal_hash"]
        jid = r["id"]
        # Skip if already flagged
        if any(tj["job_id"] == jid for tj in tampered_jobs):
            continue
            
        if not stored_seal:
            tampered_jobs.append({
                "job_id": jid,
                "reason": "Missing seal on Filed job",
                "stored_seal": None,
                "expected_seal": None,
            })
            continue
            
        payload = build_job_seal_payload(r)
        expected_seal = compute_job_seal(payload, JOB_SEAL_KEY)
        if not hmac.compare_digest(expected_seal, stored_seal):
            tampered_jobs.append({
                "job_id": jid,
                "reason": "HMAC seal mismatch (content modified directly in DB)",
                "stored_seal": stored_seal,
                "expected_seal": expected_seal,
            })
            
    return tampered_jobs

def record_security_denial(
    conn: sqlite3.Connection,
    actor_id: str,
    action: str,
    job_id: str,
    denial_reason: str,
    now_epoch: Optional[float] = None,
) -> Optional[int]:
    """
    Record denial and check for probe attacks.
    MITRE ATT&CK:
    - T1078 (Valid Accounts - scanning unauthorized permissions)
    - T1087 (Account Discovery / Permission enumeration)
    Writes an ANOMALY event to ledger if threshold exceeded.
    """
    now = now_epoch if now_epoch is not None else time.time()
    conn.execute(
        "INSERT INTO security_events (actor_id, event_type, timestamp, details_json) VALUES (?, 'denial', ?, ?)",
        (actor_id, now, canonical_json({"action": action, "job_id": job_id, "reason": denial_reason})),
    )
    
    # Check count within sliding window
    window_start = now - PROBE_WINDOW_SECONDS
    cur = conn.execute(
        "SELECT COUNT(*) as cnt FROM security_events WHERE actor_id = ? AND event_type = 'denial' AND timestamp >= ?",
        (actor_id, window_start),
    )
    count = cur.fetchone()["cnt"]
    
    if count >= PROBE_THRESHOLD_COUNT:
        # Trigger Anomaly Ledger Event
        return record_ledger_event(
            conn=conn,
            event_type="anomaly",
            entity_type="security",
            entity_id=actor_id,
            actor_id=actor_id,
            details={
                "alert": "Excessive authorization denials (probe attack detected)",
                "denial_count": count,
                "window_seconds": PROBE_WINDOW_SECONDS,
                "mitre_attack": ["T1078", "T1087"],
                "last_denial_reason": denial_reason,
                "last_action": action,
                "last_job_id": job_id,
            },
        )
    return None

def record_filed_job_tamper_alert(
    conn: sqlite3.Connection,
    actor_id: str,
    action: str,
    job_id: str,
    details: Dict[str, Any],
) -> int:
    """
    Record an ALERT event when a write attempt is made on a Filed job.
    """
    return record_ledger_event(
        conn=conn,
        event_type="alert",
        entity_type="job",
        entity_id=job_id,
        actor_id=actor_id,
        details={
            "alert": "Unauthorized write attempt on immutable Filed job",
            "attempted_action": action,
            **details,
        },
    )
