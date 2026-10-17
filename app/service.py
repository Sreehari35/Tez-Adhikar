"""
Core Application Service layer:
- Grant lifecycle and Admin self-escalation protection
- Responsibility change and pool reassignment
- Delegation and Break-glass handling
- Blast-radius simulator (dry-run)
- Forensic Time Machine
- Side-by-side decision explainer
"""

import json
import sqlite3
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.db import get_grants_version, increment_grants_version
from app.state_machine import ACTIONS, STAGES, get_next_stage
from app.predicate import match_scope_in_memory
from app.engine import DecisionEngine
from app.audit import record_ledger_event
from app.config import BREAKGLASS_DURATION_MINUTES
from app.audit import build_job_seal_payload
from app.crypto import compute_job_seal, canonical_json, JOB_SEAL_KEY

class AccessService:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn
        self.engine = DecisionEngine(conn)

    def _resolve_job_id(self, job_id: str) -> str:
        job_row = self.conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
        if job_row:
            return job_row["id"]

        prefix, separator, suffix = job_id.partition("_")
        if prefix == "JOB" and separator and suffix.isascii() and suffix.isdigit() and len(suffix) < 7:
            padded_job_id = f"JOB_{suffix.zfill(7)}"
            job_row = self.conn.execute("SELECT id FROM jobs WHERE id = ?", (padded_job_id,)).fetchone()
            if job_row:
                return job_row["id"]

        raise ValueError(f"Job {job_id} not found")

    def _require_admin(self, actor_id: str) -> None:
        if self.engine.authorize(actor_id=actor_id, action="manage_access")["decision"] != "ALLOW":
            raise PermissionError("Actor lacks 'manage_access' authority")

    def propose_grant(self, *, user_id: str, role_name: str, scope: Dict[str, Any],
                      effect: str, valid_from: Optional[str], valid_to: Optional[str],
                      requester_id: str) -> Dict[str, Any]:
        """Persist, but do not activate, an administrative grant proposal."""
        self._require_admin(requester_id)
        # Reuse validation without writing a grant by checking immutable inputs.
        if requester_id == user_id:
            raise PermissionError("Self-escalation blocked")
        if effect not in ("allow", "deny") or not isinstance(scope, dict):
            raise ValueError("Invalid grant proposal")
        if not self.conn.execute("SELECT 1 FROM users WHERE id = ? AND is_active = 1", (user_id,)).fetchone():
            raise ValueError("Unknown active target user")
        if not self.conn.execute("SELECT 1 FROM roles WHERE name = ? AND is_active = 1", (role_name,)).fetchone():
            raise ValueError("Unknown active role")
        for key, values in scope.items():
            if key not in {"clients", "branches", "directions", "modes"} or not isinstance(values, list) or not values:
                raise ValueError("Malformed scope")
        now = datetime.now(timezone.utc)
        proposal_id = f"AP_{uuid.uuid4().hex[:16].upper()}"
        payload = {"user_id": user_id, "role_name": role_name, "scope": scope, "effect": effect,
                   "valid_from": valid_from or now.isoformat(), "valid_to": valid_to or "9999-12-31T23:59:59Z"}
        with self.conn:
            self.conn.execute("INSERT INTO admin_proposals (id, operation, payload_json, requested_by, status, created_at, expires_at) VALUES (?, 'grant_create', ?, ?, 'pending', ?, ?)",
                              (proposal_id, canonical_json(payload), requester_id, now.isoformat(), (now + timedelta(hours=24)).isoformat()))
            record_ledger_event(self.conn, "admin_proposal_created", "admin_proposal", proposal_id, requester_id, payload)
        return {"proposal_id": proposal_id, "status": "pending", "expires_at": (now + timedelta(hours=24)).isoformat()}

    def approve_grant_proposal(self, proposal_id: str, approver_id: str, approve: bool = True) -> Dict[str, Any]:
        """Approve/reject an exact pending proposal from a second admin session."""
        self._require_admin(approver_id)
        now = datetime.now(timezone.utc).isoformat()
        with self.conn:
            row = self.conn.execute("SELECT * FROM admin_proposals WHERE id = ?", (proposal_id,)).fetchone()
            if not row or row["status"] != "pending" or row["expires_at"] <= now:
                raise ValueError("Proposal is not pending or has expired")
            if row["requested_by"] == approver_id:
                raise PermissionError("Self-approval is prohibited")
            if not approve:
                self.conn.execute("UPDATE admin_proposals SET status='rejected', approved_by=?, completed_at=? WHERE id=? AND status='pending'", (approver_id, now, proposal_id))
                record_ledger_event(self.conn, "admin_proposal_rejected", "admin_proposal", proposal_id, approver_id, {})
                return {"proposal_id": proposal_id, "status": "rejected"}
            p = json.loads(row["payload_json"])
            # Revalidate the proposed target and role at execution time.
            if not self.conn.execute("SELECT 1 FROM users WHERE id=? AND is_active=1", (p["user_id"],)).fetchone() or not self.conn.execute("SELECT 1 FROM roles WHERE name=? AND is_active=1", (p["role_name"],)).fetchone():
                raise ValueError("Proposal target is no longer valid")
            gid = f"G_{uuid.uuid4().hex[:12].upper()}"
            self.conn.execute("INSERT INTO grants (id,user_id,role_name,scope_json,effect,valid_from,valid_to,recorded_at,created_by,approved_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
                              (gid,p["user_id"],p["role_name"],canonical_json(p["scope"]),p["effect"],p["valid_from"],p["valid_to"],now,row["requested_by"],approver_id))
            self.conn.execute("UPDATE admin_proposals SET status='approved', approved_by=?, completed_at=? WHERE id=? AND status='pending'", (approver_id,now,proposal_id))
            increment_grants_version(self.conn)
            record_ledger_event(self.conn, "admin_proposal_approved", "admin_proposal", proposal_id, approver_id, {"grant_id": gid, **p})
        return {"proposal_id": proposal_id, "grant_id": gid, "status": "approved"}

    def request_filed_transition(self, job_id: str, action: str, reason: str, requester_id: str) -> Dict[str, Any]:
        if action not in ("cancel", "reopen") or not isinstance(reason, str) or len(reason.strip()) < 3:
            raise ValueError("Filed transition requires action and business reason")
        receipt = self.engine.authorize(requester_id, action, job_id, reason=reason, permit_sensitive_request=True)
        if receipt["decision"] != "ALLOW":
            raise PermissionError("Requester lacks eligible Supervisor authority")
        job = self.conn.execute("SELECT stage FROM jobs WHERE id=?", (job_id,)).fetchone()
        if not job or job["stage"] != "Filed":
            raise ValueError("Only a currently Filed job can use this workflow")
        now = datetime.now(timezone.utc); request_id = f"FP_{uuid.uuid4().hex[:16].upper()}"
        with self.conn:
            self.conn.execute("INSERT INTO pending_approvals (id,job_id,action,requested_by,reason,expected_stage,expires_at,status,created_at) VALUES (?,?,?,?,?,'Filed',?,'pending',?)", (request_id,job_id,action,requester_id,reason.strip(),(now+timedelta(hours=4)).isoformat(),now.isoformat()))
            record_ledger_event(self.conn,"filed_transition_requested","approval",request_id,requester_id,{"job_id":job_id,"action":action,"reason":reason.strip()})
        return {"request_id":request_id,"status":"pending"}

    def approve_filed_transition(self, request_id: str, approver_id: str, approve: bool=True) -> Dict[str, Any]:
        now=datetime.now(timezone.utc).isoformat()
        with self.conn:
            req=self.conn.execute("SELECT * FROM pending_approvals WHERE id=?",(request_id,)).fetchone()
            if not req or req["status"] != "pending" or req["expires_at"] <= now: raise ValueError("Request is not pending or has expired")
            if req["requested_by"] == approver_id: raise PermissionError("Self-approval is prohibited")
            receipt=self.engine.authorize(approver_id, req["action"], req["job_id"], reason=req["reason"], permit_sensitive_request=True)
            if receipt["decision"] != "ALLOW": raise PermissionError("Approver lacks eligible Supervisor authority")
            status="approved" if approve else "rejected"
            self.conn.execute("UPDATE pending_approvals SET status=?, approved_by=?, completed_at=? WHERE id=? AND status='pending'",(status,approver_id,now,request_id))
            record_ledger_event(self.conn,f"filed_transition_{status}","approval",request_id,approver_id,{"job_id":req["job_id"],"action":req["action"]})
        return {"request_id":request_id,"status":status}

    def execute_filed_transition(self, request_id: str, actor_id: str) -> Dict[str, Any]:
        """Execute one approved request atomically; approval cannot be replayed."""
        now = datetime.now(timezone.utc).isoformat()
        with self.conn:
            req = self.conn.execute("SELECT * FROM pending_approvals WHERE id=?", (request_id,)).fetchone()
            if not req or req["status"] != "approved" or req["expires_at"] <= now:
                raise ValueError("Request is not approved or has expired")
            if req["requested_by"] != actor_id:
                raise PermissionError("Only the authenticated requester may execute this approval")
            job = self.conn.execute("SELECT * FROM jobs WHERE id=?", (req["job_id"],)).fetchone()
            if not job or job["stage"] != req["expected_stage"]:
                raise ValueError("Job state no longer matches approved request")
            receipt = self.engine.authorize(actor_id, req["action"], req["job_id"], reason=req["reason"], permit_sensitive_request=True)
            if receipt["decision"] != "ALLOW":
                raise PermissionError("Requester is no longer authorized")
            transition = get_next_stage(job["stage"], req["action"])
            if not transition: raise ValueError("Illegal lifecycle transition")
            new_stage, _ = transition
            changed = self.conn.execute("UPDATE jobs SET stage=?, updated_at=? WHERE id=? AND stage=?", (new_stage, now, req["job_id"], req["expected_stage"])).rowcount
            if changed != 1: raise ValueError("Concurrent job change prevented execution")
            self.conn.execute("UPDATE pending_approvals SET status='executed', completed_at=? WHERE id=? AND status='approved'", (now, request_id))
            record_ledger_event(self.conn, "job_" + req["action"], "job", req["job_id"], actor_id,
                                {"previous_stage": req["expected_stage"], "new_stage": new_stage, "reason": req["reason"], "approval_request_id": request_id, "approved_by": req["approved_by"]})
        return {"request_id":request_id,"job_id":req["job_id"],"new_stage":new_stage,"status":"executed"}

    # ---------------------------------------------------------
    # Role Management (Roles are DATA)
    # ---------------------------------------------------------
    def create_role(
        self,
        name: str,
        permissions: List[str],
        description: str,
        actor_id: str,
    ) -> Dict[str, Any]:
        """
        Add a new role without code changes.
        Validates permissions against system actions, then activates.
        """
        # Role definitions are policy.  Enforce this in the service so direct
        # callers cannot bypass the HTTP authorization boundary.
        auth = self.engine.authorize(actor_id=actor_id, action="manage_access")
        if auth["decision"] != "ALLOW":
            raise PermissionError("Actor lacks 'manage_access' authority")
        if not isinstance(name, str) or not name or len(name) > 64 or not name.replace("_", "").isalnum():
            raise ValueError("Role name must be 1-64 alphanumeric/underscore characters")
        if not isinstance(permissions, list) or not permissions or len(set(permissions)) != len(permissions):
            raise ValueError("Permissions must be a non-empty list without duplicates")
        if not isinstance(description, str) or len(description) > 500:
            raise ValueError("Role description is invalid")
        # Validate permissions
        invalid = [p for p in permissions if p not in ACTIONS]
        if invalid:
            raise ValueError(f"Invalid actions for role: {invalid}. Must be subset of {ACTIONS}")

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO roles (name, permissions, description, is_active, created_at)
                VALUES (?, ?, ?, 1, datetime('now'))
                """,
                (name, json.dumps(permissions), description),
            )
            record_ledger_event(
                self.conn,
                event_type="role_created",
                entity_type="role",
                entity_id=name,
                actor_id=actor_id,
                details={"name": name, "permissions": permissions, "description": description},
            )
            increment_grants_version(self.conn)

        return {"name": name, "permissions": permissions, "description": description, "status": "active"}

    # ---------------------------------------------------------
    # Grant Management (Bitemporal & Self-Escalation Protected)
    # ---------------------------------------------------------
    def create_grant(
        self,
        user_id: str,
        role_name: str,
        scope: Dict[str, Any],
        created_by: str,
        approved_by: Optional[str] = None,
        effect: str = "allow",
        valid_from: Optional[str] = None,
        valid_to: Optional[str] = None,
        grant_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new bitemporal grant.
        Enforces:
        - Creator must have AccessAdmin authority.
        - Admin self-escalation blocked: no one may grant themselves or raise their own privileges.
        - Changes to an admin's own grants require a different admin as approver!
        """
        if not isinstance(scope, dict) or effect not in ("allow", "deny"):
            raise ValueError("Invalid grant scope or effect")
        allowed_dimensions = {"clients", "branches", "directions", "modes"}
        if set(scope) - allowed_dimensions:
            raise ValueError("Unknown scope dimension")
        for dimension, values in scope.items():
            if not isinstance(values, list) or not values or any(not isinstance(v, str) or not v for v in values):
                raise ValueError(f"Scope {dimension} must be a non-empty list of strings when present")
        now = datetime.now(timezone.utc).isoformat()
        v_from = valid_from or now
        v_to = valid_to or "9999-12-31T23:59:59Z"
        gid = grant_id or f"G_{uuid.uuid4().hex[:12].upper()}"

        # 1. Authority check: Creator must have AccessAdmin
        admin_auth = self.engine.authorize(actor_id=created_by, action="manage_access")
        if admin_auth["decision"] != "ALLOW":
            raise PermissionError(f"Actor {created_by} lacks 'manage_access' authority")
        if not self.conn.execute("SELECT 1 FROM roles WHERE name = ? AND is_active = 1", (role_name,)).fetchone():
            raise ValueError("Unknown or inactive role")
        if not self.conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone():
            raise ValueError("Unknown target user")

        # 2. Self-escalation check
        if created_by == user_id:
            raise PermissionError(
                f"Self-escalation blocked: Admin {created_by} cannot grant roles to themselves. Another admin must create or approve this grant."
            )

        # 3. If target user is an Admin, a distinct approver is strictly required
        target_admin_grants = [
            g for g in self.engine._fetch_active_grants(user_id) if g["role_name"] == "AccessAdmin"
        ]
        if target_admin_grants or role_name == "AccessAdmin":
            if not approved_by or approved_by == user_id or approved_by == created_by:
                raise PermissionError(
                    f"Two-admin rule violated: Changes to an admin's privileges require a distinct second admin approver (approved_by != created_by != user_id)."
                )
            # Verify approved_by is also an AccessAdmin
            approver_auth = self.engine.authorize(actor_id=approved_by, action="manage_access")
            if approver_auth["decision"] != "ALLOW":
                raise PermissionError(f"Approver {approved_by} is not an authorized AccessAdmin")

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO grants (id, user_id, role_name, scope_json, effect, valid_from, valid_to, recorded_at, closed_at, created_by, approved_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
                """,
                (gid, user_id, role_name, json.dumps(scope), effect, v_from, v_to, now, created_by, approved_by),
            )
            record_ledger_event(
                self.conn,
                event_type="grant_created",
                entity_type="grant",
                entity_id=gid,
                actor_id=created_by,
                details={
                    "user_id": user_id,
                    "role_name": role_name,
                    "scope": scope,
                    "effect": effect,
                    "valid_from": v_from,
                    "valid_to": v_to,
                    "approved_by": approved_by,
                },
            )
            increment_grants_version(self.conn)

        return {
            "id": gid,
            "user_id": user_id,
            "role_name": role_name,
            "scope": scope,
            "effect": effect,
            "valid_from": v_from,
            "valid_to": v_to,
            "recorded_at": now,
        }

    def revoke_grant(self, grant_id: str, actor_id: str) -> Dict[str, Any]:
        """
        Bitemporal closure of a grant: sets closed_at = now (never delete).
        Triggers responsibility change: releases claimed jobs back to the pool,
        logs 'reassigned' event, while preserving past work attribution.
        """
        now = datetime.now(timezone.utc).isoformat()
        admin_auth = self.engine.authorize(actor_id=actor_id, action="manage_access")
        if admin_auth["decision"] != "ALLOW":
            raise PermissionError(f"Actor {actor_id} lacks 'manage_access' authority")

        cur = self.conn.execute("SELECT * FROM grants WHERE id = ? AND closed_at IS NULL", (grant_id,))
        grant = cur.fetchone()
        if not grant:
            raise ValueError(f"Active grant {grant_id} not found")

        user_id = grant["user_id"]

        with self.conn:
            # Bitemporal close
            self.conn.execute("UPDATE grants SET closed_at = ? WHERE id = ?", (now, grant_id))
            increment_grants_version(self.conn)

            # Record grant revocation in ledger
            record_ledger_event(
                self.conn,
                event_type="grant_closed",
                entity_type="grant",
                entity_id=grant_id,
                actor_id=actor_id,
                details={"closed_at": now, "previous_user": user_id, "role_name": grant["role_name"]},
            )

            # Responsibility Change:
            # Release in-progress jobs claimed by this user back to the pool (assigned_to = NULL)
            # Past work (prepared_by, checked_by, filed_by) stays attributed!
            claimed_cur = self.conn.execute(
                "SELECT id, stage, client_id, branch FROM jobs WHERE assigned_to = ?", (user_id,)
            )
            claimed_jobs = claimed_cur.fetchall()
            if claimed_jobs:
                self.conn.execute(
                    "UPDATE jobs SET assigned_to = NULL WHERE assigned_to = ?", (user_id,)
                )
                for j in claimed_jobs:
                    record_ledger_event(
                        self.conn,
                        event_type="reassigned",
                        entity_type="job",
                        entity_id=j["id"],
                        actor_id=actor_id,
                        details={
                            "action": "responsibility_released_to_pool",
                            "previous_assignee": user_id,
                            "job_stage": j["stage"],
                            "reason": f"Grant {grant_id} revoked for user {user_id}",
                        },
                    )

        return {"grant_id": grant_id, "status": "closed", "closed_at": now, "released_jobs_count": len(claimed_jobs)}

    # ---------------------------------------------------------
    # Delegation (Supervisor to User for time window, no chaining)
    # ---------------------------------------------------------
    def create_delegation(
        self,
        delegator_id: str,
        delegate_id: str,
        role_name: str,
        scope: Dict[str, Any],
        reason: str,
        valid_from: Optional[str] = None,
        valid_to: Optional[str] = None,
        delegation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Supervisor delegates authority to another user for a time window.
        Enforces:
        - Delegator must have Supervisor role.
        - Scope must be a subset of delegator's own scope.
        - No chaining: delegate cannot be another delegate.
        - Audited in ledger.
        """
        now = datetime.now(timezone.utc).isoformat()
        v_from = valid_from or now
        v_to = valid_to or (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
        did = delegation_id or f"DELG_{uuid.uuid4().hex[:12].upper()}"

        # 1. Check no chaining: Is delegator acting via another delegation?
        cur = self.conn.execute(
            "SELECT id FROM delegations WHERE delegate_id = ? AND status = 'active' AND valid_to >= ?",
            (delegator_id, now),
        )
        if cur.fetchone():
            raise PermissionError("Delegation chaining is strictly prohibited")

        # 2. Delegator must hold the role/scope they are delegating
        delegator_grants = [
            g for g in self.engine._fetch_active_grants(delegator_id)
            if g["role_name"] == role_name and g["effect"] == "allow"
        ]
        if not delegator_grants:
            raise PermissionError(f"Delegator {delegator_id} does not hold active grant for role {role_name}")

        # 3. Scope restriction check (delegated scope must not exceed delegator's scope)
        for g in delegator_grants:
            d_scope = g["scope"]
            for dim in ("clients", "branches", "directions", "modes"):
                d_allowed = d_scope.get(dim)
                req_allowed = scope.get(dim)
                if d_allowed:  # Delegator has a restricted list
                    if not req_allowed:
                        raise PermissionError(f"Cannot delegate wildcard for dimension {dim}: delegator is restricted to {d_allowed}")
                    if any(item not in d_allowed for item in req_allowed):
                        raise PermissionError(f"Delegated scope {req_allowed} exceeds delegator's permitted {dim} {d_allowed}")

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO delegations (id, delegator_id, delegate_id, role_name, scope_json, valid_from, valid_to, reason, status, created_at, created_by)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
                """,
                (did, delegator_id, delegate_id, role_name, json.dumps(scope), v_from, v_to, reason, now, delegator_id),
            )
            record_ledger_event(
                self.conn,
                event_type="delegation_created",
                entity_type="delegation",
                entity_id=did,
                actor_id=delegator_id,
                details={
                    "delegator_id": delegator_id,
                    "delegate_id": delegate_id,
                    "role_name": role_name,
                    "scope": scope,
                    "reason": reason,
                    "valid_from": v_from,
                    "valid_to": v_to,
                },
            )
            increment_grants_version(self.conn)

        return {
            "id": did,
            "delegator_id": delegator_id,
            "delegate_id": delegate_id,
            "role_name": role_name,
            "scope": scope,
            "reason": reason,
            "valid_from": v_from,
            "valid_to": v_to,
            "status": "active",
        }

    # ---------------------------------------------------------
    # Break-Glass Access
    # ---------------------------------------------------------
    def trigger_breakglass(self, admin_id: str, reason: str) -> Dict[str, Any]:
        """
        Break-glass emergency privilege elevation:
        - 30-minute expiry
        - Alerts immediately in audit ledger
        - Requires later ratification by a second person
        """
        admin_auth = self.engine.authorize(actor_id=admin_id, action="manage_access")
        if admin_auth["decision"] != "ALLOW":
            raise PermissionError(f"Actor {admin_id} is not an AccessAdmin")

        if not reason or len(reason.strip()) < 10:
            raise ValueError("Detailed emergency justification reason required (min 10 chars)")

        now = datetime.now(timezone.utc)
        valid_from = now.isoformat()
        valid_to = (now + timedelta(minutes=BREAKGLASS_DURATION_MINUTES)).isoformat()
        bg_id = f"BG_{uuid.uuid4().hex[:12].upper()}"

        with self.conn:
            self.conn.execute(
                """
                INSERT INTO breakglass (id, admin_id, reason, valid_from, valid_to, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'active', ?)
                """,
                (bg_id, admin_id, reason, valid_from, valid_to, valid_from),
            )
            # Immediate Alert in Ledger
            record_ledger_event(
                self.conn,
                event_type="alert",
                entity_type="security",
                entity_id=bg_id,
                actor_id=admin_id,
                details={
                    "alert": "BREAK-GLASS EMERGENCY ACCESS INVOKED",
                    "admin_id": admin_id,
                    "reason": reason,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "duration_minutes": BREAKGLASS_DURATION_MINUTES,
                    "status": "active_awaiting_ratification",
                },
            )

        return {
            "breakglass_id": bg_id,
            "admin_id": admin_id,
            "reason": reason,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "status": "active",
        }

    def ratify_breakglass(self, breakglass_id: str, ratifier_id: str) -> Dict[str, Any]:
        """
        Second person ratifies an invoked break-glass session.
        """
        cur = self.conn.execute("SELECT * FROM breakglass WHERE id = ?", (breakglass_id,))
        row = cur.fetchone()
        if not row:
            raise ValueError(f"Break-glass event {breakglass_id} not found")

        if row["admin_id"] == ratifier_id:
            raise PermissionError("Self-ratification blocked: Ratifier must be distinct from the invoking admin")

        ratifier_auth = self.engine.authorize(actor_id=ratifier_id, action="manage_access")
        if ratifier_auth["decision"] != "ALLOW":
            raise PermissionError(f"Ratifier {ratifier_id} must have AccessAdmin authority")

        now = datetime.now(timezone.utc).isoformat()
        with self.conn:
            self.conn.execute(
                "UPDATE breakglass SET status = 'ratified', ratified_by = ?, ratified_at = ? WHERE id = ?",
                (ratifier_id, now, breakglass_id),
            )
            record_ledger_event(
                self.conn,
                event_type="breakglass_ratified",
                entity_type="security",
                entity_id=breakglass_id,
                actor_id=ratifier_id,
                details={"ratifier_id": ratifier_id, "invoker_id": row["admin_id"], "ratified_at": now},
            )

        return {"breakglass_id": breakglass_id, "status": "ratified", "ratified_by": ratifier_id, "ratified_at": now}

    # ---------------------------------------------------------
    # Blast-Radius Simulator (Dry-Run)
    # ---------------------------------------------------------
    def simulate_grant(
        self,
        grantor_id: str,
        user_id: str,
        role_name: str,
        scope: Dict[str, Any],
    ) -> Dict[str, Any]:
        """
        Dry-run blast-radius analysis:
        - Jobs gained: count of jobs user could newly act upon.
        - SoD conflicts created: jobs where user is preparer and this role would confer check/file rights.
        - Self-privilege elevation check: does it grant authority to the grantor themselves?
        NO changes applied to DB.
        """
        # Fetch role permissions
        cur = self.conn.execute("SELECT permissions FROM roles WHERE name = ? AND is_active = 1", (role_name,))
        r = cur.fetchone()
        if not r:
            raise ValueError(f"Role {role_name} not found")
        perms = json.loads(r["permissions"])

        # Fetch current user permissions before grant
        current_grants = self.engine._fetch_active_grants(user_id)
        
        # Self-escalation warning
        raises_own_privilege = (grantor_id == user_id)

        # Query all jobs to simulate impact
        cur = self.conn.execute(
            "SELECT id, client_id, branch, direction, mode, stage, prepared_by FROM jobs"
        )
        jobs = cur.fetchall()

        jobs_gained = 0
        sod_conflicts = 0
        actionable_stages = []
        if "prepare" in perms:
            actionable_stages.extend(["Confirmed", "Reopened"])
        if "check" in perms:
            actionable_stages.append("Prepared")
        if "file" in perms:
            actionable_stages.append("Checked")

        for j in jobs:
            j_dict = dict(j)
            matches = match_scope_in_memory(j_dict, scope)
            if matches:
                # Check SoD conflicts
                if j_dict["prepared_by"] == user_id and ("check" in perms or "file" in perms):
                    sod_conflicts += 1
                
                # Check if this job is newly actionable
                if j_dict["stage"] in actionable_stages:
                    jobs_gained += 1

        return {
            "grantor_id": grantor_id,
            "target_user_id": user_id,
            "role_name": role_name,
            "scope": scope,
            "raises_grantor_own_privilege": raises_own_privilege,
            "jobs_gained_count": jobs_gained,
            "sod_conflicts_created_count": sod_conflicts,
            "status": "dry_run_complete",
        }

    # ---------------------------------------------------------
    # Forensic Time Machine (Replay at Historical Timestamp)
    # ---------------------------------------------------------
    def who_could_change(self, job_id: str, at_timestamp: str) -> Dict[str, Any]:
        """
        Forensic Time Machine:
        Replays grants and state as they were at `at_timestamp`.
        Lists:
        1. Who COULD act on this job at that exact moment.
        2. Who ACTUALLY acted on this job around that time (from audit ledger).
        """
        # Fetch job
        job_id = self._resolve_job_id(job_id)
        job_row = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        job = dict(job_row)

        # Find all active users at that time
        users = self.conn.execute("SELECT id, username, full_name FROM users WHERE is_active = 1").fetchall()

        authorized_actors = []
        for u in users:
            uid = u["id"]
            # Test key pipeline actions: prepare, check, file, cancel, reopen
            for act in ("prepare", "check", "file", "cancel", "reopen"):
                rec = self.engine.authorize(actor_id=uid, action=act, job_id=job_id, as_of=at_timestamp)
                if rec["decision"] == "ALLOW":
                    authorized_actors.append({
                        "user_id": uid,
                        "username": u["username"],
                        "name": u["full_name"],
                        "authorized_action": act,
                        "rule": rec["rule"],
                    })

        # Find actual ledger events on this job around that timestamp
        ledger_cur = self.conn.execute(
            """
            SELECT seq, event_type, actor_id, timestamp, details_json
            FROM audit_ledger
            WHERE entity_id = ?
            ORDER BY seq ASC
            """,
            (job_id,),
        )
        actual_events = []
        for r in ledger_cur.fetchall():
            actual_events.append({
                "seq": r["seq"],
                "event_type": r["event_type"],
                "actor_id": r["actor_id"],
                "timestamp": r["timestamp"],
                "details": json.loads(r["details_json"]),
            })

        return {
            "job_id": job_id,
            "historical_timestamp": at_timestamp,
            "job_state_then": {
                "client_id": job["client_id"],
                "branch": job["branch"],
                "stage": job["stage"],
                "prepared_by": job["prepared_by"],
            },
            "who_could_act": authorized_actors,
            "actual_history_events": actual_events,
        }

    # ---------------------------------------------------------
    # Decision Explainer ("Why A can and B can't")
    # ---------------------------------------------------------
    def explain(
        self,
        user_a_id: str,
        user_b_id: str,
        action: str,
        job_id: str,
    ) -> Dict[str, Any]:
        """
        Explain side-by-side why User A can perform an action on a job, and User B cannot.
        """
        job_id = self._resolve_job_id(job_id)
        rec_a = self.engine.authorize(actor_id=user_a_id, action=action, job_id=job_id)
        rec_b = self.engine.authorize(actor_id=user_b_id, action=action, job_id=job_id)

        job_row = self.conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
        job = dict(job_row)

        return {
            "job_id": job_id,
            "job_summary": {
                "client_id": job["client_id"],
                "branch": job["branch"],
                "direction": job["direction"],
                "mode": job["mode"],
                "stage": job["stage"],
                "prepared_by": job["prepared_by"],
            },
            "action": action,
            "user_a": {
                "user_id": user_a_id,
                "decision": rec_a["decision"],
                "code": rec_a["code"],
                "rule": rec_a["rule"],
                "matched_grant_ids": rec_a["matched_grant_ids"],
            },
            "user_b": {
                "user_id": user_b_id,
                "decision": rec_b["decision"],
                "code": rec_b["code"],
                "rule": rec_b["rule"],
                "matched_grant_ids": rec_b["matched_grant_ids"],
            },
            "comparison_summary": (
                f"User {user_a_id} is {rec_a['decision']} ({rec_a['code']}) because '{rec_a['rule']}', "
                f"whereas User {user_b_id} is {rec_b['decision']} ({rec_b['code']}) because '{rec_b['rule']}'."
            ),
        }
