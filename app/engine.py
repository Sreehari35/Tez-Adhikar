"""
Core Authorization and Decision Engine for Nagarkot Access Control Service.
Implements fail-closed decision pipeline, SoD enforcement, delegation handling,
two-person approval for filed jobs, and cryptographically signed decision receipts.
"""

import json
import sqlite3
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.db import get_grants_version
from app.crypto import sign_decision_receipt, canonical_json
from app.state_machine import is_transition_legal, get_next_stage
from app.predicate import match_scope_in_memory
from app.audit import record_ledger_event, record_security_denial

class DecisionEngine:
    """
    Evaluates authorization requests in strict fail-closed order.
    Order:
      1. State Machine legality
      2. Service (Parser) role restrictions
      3. Explicit Deny grants
      4. Matching Allow grant (direct or active delegation)
      5. Separation of Duties (SoD) enforcement
      6. Two-person approval for Filed job cancel/reopen
      7. Unexpected conditions -> Fail-closed INDETERMINATE
    """

    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def _fetch_user(self, user_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (user_id,))
        return cur.fetchone()

    def _fetch_job(self, job_id: str) -> Optional[sqlite3.Row]:
        cur = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
        row = cur.fetchone()
        if not row and job_id.startswith("JOB_"):
            num_part = job_id.replace("JOB_", "")
            if num_part.isdigit():
                cur = self.conn.execute("SELECT * FROM jobs WHERE id = ? OR id = ?", (f"JOB_{int(num_part):04d}", f"JOB_{int(num_part):07d}"))
                row = cur.fetchone()
        return row

    def _fetch_active_grants(self, user_id: str, as_of: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch active grants bitemporally:
        recorded_at <= as_of AND (closed_at IS NULL OR closed_at > as_of)
        AND valid_from <= as_of AND valid_to >= as_of
        """
        now = as_of or datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            """
            SELECT g.*, r.permissions
            FROM grants g
            JOIN roles r ON g.role_name = r.name
            WHERE g.user_id = ?
              AND g.recorded_at <= ?
              AND (g.closed_at IS NULL OR g.closed_at > ?)
              AND g.valid_from <= ?
              AND g.valid_to >= ?
              AND r.is_active = 1
            """,
            (user_id, now, now, now, now),
        )
        grants = []
        for r in cur.fetchall():
            try:
                scope = json.loads(r["scope_json"])
            except Exception:
                scope = {}
            try:
                perms = json.loads(r["permissions"])
            except Exception:
                perms = []
            grants.append({
                "id": r["id"],
                "role_name": r["role_name"],
                "effect": r["effect"],
                "scope": scope,
                "permissions": perms,
                "source": "direct",
                "delegator_id": None,
            })
        return grants

    def _fetch_active_delegations(self, user_id: str, as_of: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Fetch active delegations where user is the delegate.
        Delegator must also have an active grant matching the delegated role!
        """
        now = as_of or datetime.now(timezone.utc).isoformat()
        cur = self.conn.execute(
            """
            SELECT d.*, r.permissions
            FROM delegations d
            JOIN roles r ON d.role_name = r.name
            WHERE d.delegate_id = ?
              AND d.status = 'active'
              AND d.valid_from <= ?
              AND d.valid_to >= ?
              AND r.is_active = 1
            """,
            (user_id, now, now),
        )
        delegations = []
        for r in cur.fetchall():
            try:
                scope = json.loads(r["scope_json"])
            except Exception:
                scope = {}
            try:
                perms = json.loads(r["permissions"])
            except Exception:
                perms = []
            
            # Verify delegator still possesses this grant
            delegator_grants = self._fetch_active_grants(r["delegator_id"], as_of=now)
            has_role = any(
                dg["role_name"] == r["role_name"] and dg["effect"] == "allow"
                for dg in delegator_grants
            )
            if has_role:
                delegations.append({
                    "id": f"delg_{r['id']}",
                    "role_name": r["role_name"],
                    "effect": "allow",
                    "scope": scope,
                    "permissions": perms,
                    "source": "delegation",
                    "delegator_id": r["delegator_id"],
                })
        return delegations

    def authorize(
        self,
        actor_id: str,
        action: str,
        job_id: Optional[str] = None,
        job_data: Optional[Dict[str, Any]] = None,
        reason: Optional[str] = None,
        second_approver_id: Optional[str] = None,
        as_of: Optional[str] = None,
        permit_sensitive_request: bool = False,
    ) -> Dict[str, Any]:
        """
        Evaluate authorization request and return signed decision receipt.
        Fail-closed by design: returns INDETERMINATE on any failure or missing state.
        """
        now = as_of or datetime.now(timezone.utc).isoformat()
        policy_version = get_grants_version(self.conn)

        try:
            # 0. User Existence & Active Check
            user = self._fetch_user(actor_id)
            if not user:
                return self._build_receipt(
                    "DENY", "DENIED_USER_NOT_FOUND", "user_validation", [], actor_id, action, job_id, policy_version, now
                )

            # AccessAdmin check: AccessAdmin has NO job-action powers
            if action != "manage_access":
                # Check if user only holds AccessAdmin
                user_grants = self._fetch_active_grants(actor_id, as_of=now)
                only_admin = user_grants and all(g["role_name"] == "AccessAdmin" for g in user_grants)
                if only_admin:
                    return self._build_receipt(
                        "DENY", "DENIED_ADMIN_NO_JOB_ACTION", "admin_separation", [], actor_id, action, job_id, policy_version, now
                    )

            if action == "manage_access":
                # Manage access requires AccessAdmin
                admin_grants = [g["id"] for g in self._fetch_active_grants(actor_id, as_of=now) if g["role_name"] == "AccessAdmin" and g["effect"] == "allow"]
                if admin_grants:
                    return self._build_receipt(
                        "ALLOW", "ALLOWED", "admin_grant", admin_grants, actor_id, action, job_id, policy_version, now
                    )
                return self._build_receipt(
                    "DENY", "DENIED_NOT_ADMIN", "admin_check", [], actor_id, action, job_id, policy_version, now
                )

            # Actions on a Job
            job = None
            if job_id:
                job_row = self._fetch_job(job_id)
                if not job_row:
                    return self._build_receipt(
                        "DENY", "DENIED_JOB_NOT_FOUND", "job_validation", [], actor_id, action, job_id, policy_version, now
                    )
                job = dict(job_row)
            elif job_data:
                job = dict(job_data)
            elif action == "create":
                job = {"stage": "Confirmed", "client_id": None, "branch": None, "direction": None, "mode": None}
            else:
                return self._build_receipt(
                    "DENY", "DENIED_NO_JOB_CONTEXT", "job_context_check", [], actor_id, action, job_id, policy_version, now
                )

            # 1. State Machine Validity
            current_stage = job.get("stage", "Confirmed")
            if not is_transition_legal(current_stage, action):
                # Write alert if write attempted on Filed job
                if current_stage == "Filed" and action in ("update", "prepare", "check", "file"):
                    record_security_denial(self.conn, actor_id, action, str(job_id or "new"), "Filed job write denied")
                return self._build_receipt(
                    "DENY", "DENIED_BY_STAGE", "state_machine_invalid_transition", [], actor_id, action, job_id, policy_version, now
                )

            # 2. Automated Parser Restrictions
            if user["is_service"]:
                # Service identity may only create/update jobs in Confirmed stage
                if action not in ("create", "update") or current_stage != "Confirmed":
                    return self._build_receipt(
                        "DENY", "DENIED_PARSER_STAGE_RESTRICTION", "parser_boundary", [], actor_id, action, job_id, policy_version, now
                    )

            # 3. ClientViewer External Restrictions
            if user["client_id"]:
                # External client user: view only, must match client_id
                if action != "view":
                    return self._build_receipt(
                        "DENY", "DENIED_CLIENT_USER_VIEW_ONLY", "client_viewer_boundary", [], actor_id, action, job_id, policy_version, now
                    )
                if job.get("client_id") and job.get("client_id") != user["client_id"]:
                    return self._build_receipt(
                        "DENY", "DENIED_CLIENT_MISMATCH", "client_boundary", [], actor_id, action, job_id, policy_version, now
                    )

            # 4. Fetch All Grants & Delegations
            direct_grants = self._fetch_active_grants(actor_id, as_of=now)
            delegated_grants = self._fetch_active_delegations(actor_id, as_of=now)
            all_grants = direct_grants + delegated_grants

            # 5. Check Explicit Deny Grants First (Fail-Closed)
            for g in all_grants:
                if g["effect"] == "deny" and action in g["permissions"]:
                    if match_scope_in_memory(job, g["scope"]):
                        record_security_denial(self.conn, actor_id, action, str(job_id or "new"), "Explicit deny grant")
                        return self._build_receipt(
                            "DENY", "DENIED_EXPLICIT_DENY", "explicit_deny_grant", [g["id"]], actor_id, action, job_id, policy_version, now
                        )

            # 6. Matching Allow Grants
            matching_allows = []
            for g in all_grants:
                if g["effect"] == "allow" and action in g["permissions"]:
                    if match_scope_in_memory(job, g["scope"]):
                        matching_allows.append(g)

            if not matching_allows:
                record_security_denial(self.conn, actor_id, action, str(job_id or "new"), "No matching allow grant")
                return self._build_receipt(
                    "DENY", "DENIED_BY_SCOPE", "no_matching_grant", [], actor_id, action, job_id, policy_version, now
                )

            matched_ids = [g["id"] for g in matching_allows]

            # 7. Separation of Duties (SoD)
            # Whoever prepared a job can NEVER check or file it, even if they hold the role or act via delegation!
            # The actor is the real person (actor_id).
            if action in ("check", "file"):
                prepared_by = job.get("prepared_by")
                if prepared_by and prepared_by == actor_id:
                    record_security_denial(
                        self.conn, actor_id, action, str(job_id), f"SoD violation: preparer {prepared_by} cannot {action}"
                    )
                    return self._build_receipt(
                        "DENY", "DENIED_BY_SOD", "separation_of_duties_preparer", matched_ids, actor_id, action, job_id, policy_version, now
                    )

            # 8. Special Sensitive Transition: Cancel / Reopen of a Filed Job
            if current_stage == "Filed" and action in ("cancel", "reopen"):
                # Must hold Supervisor role
                has_supervisor = any(g["role_name"] == "Supervisor" for g in matching_allows)
                if not has_supervisor:
                    return self._build_receipt(
                        "DENY", "DENIED_REQUIRES_SUPERVISOR", "filed_job_supervisor_required", matched_ids, actor_id, action, job_id, policy_version, now
                    )
                # Mandatory reason check
                if not reason or not reason.strip():
                    return self._build_receipt(
                        "DENY", "DENIED_MANDATORY_REASON_REQUIRED", "filed_job_reason_required", matched_ids, actor_id, action, job_id, policy_version, now
                    )
                if not permit_sensitive_request:
                    return self._build_receipt(
                        "DENY", "DENIED_REQUIRES_APPROVED_REQUEST", "filed_job_persisted_approval_required", matched_ids, actor_id, action, job_id, policy_version, now
                    )
                # A second approval is deliberately not accepted here.  It is
                # established only by AccessService's persisted request/approve
                # workflow using the approver's own authenticated principal.

            # If all checks pass: ALLOW
            return self._build_receipt(
                "ALLOW", "ALLOWED", "matching_grant", matched_ids, actor_id, action, job_id, policy_version, now
            )

        except Exception as e:
            # FAIL-CLOSED: Any unexpected condition returns DENY with code INDETERMINATE and is logged
            try:
                record_ledger_event(
                    self.conn,
                    event_type="error",
                    entity_type="security",
                    entity_id=actor_id,
                    actor_id=actor_id,
                    details={"error": str(e), "action": action, "job_id": job_id},
                )
            except Exception:
                pass
            return self._build_receipt(
                "DENY", "INDETERMINATE", "system_exception_fail_closed", [], actor_id, action, job_id, policy_version, now
            )

    def _build_receipt(
        self,
        decision: str,
        code: str,
        rule: str,
        matched_grant_ids: List[str],
        actor_id: str,
        action: str,
        job_id: Optional[str],
        policy_version: int,
        timestamp: str,
    ) -> Dict[str, Any]:
        """
        Build receipt dictionary and compute cryptographic HMAC signature.
        """
        receipt = {
            "decision": decision,
            "code": code,
            "rule": rule,
            "matched_grant_ids": matched_grant_ids,
            "actor_id": str(actor_id),
            "action": action,
            "job_id": str(job_id) if job_id else None,
            "policy_version": policy_version,
            "timestamp": timestamp,
        }
        receipt["signature"] = sign_decision_receipt(receipt)
        return receipt
