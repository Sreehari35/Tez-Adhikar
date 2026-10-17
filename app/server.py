"""
Lightweight REST API Server and Multi-Page Web Dispatcher for Tez Adhikar.
Standard library only: http.server, json, urllib.parse, pathlib.

Authentication:
  Human users:    Authorization: Bearer <token>   (obtained via POST /auth/login)
  Service accts:  X-Api-Key: <key>                (svc_parser only)
  Public routes:  POST /auth/login, GET / (HTML), static assets
"""

import json
import sqlite3
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Dict, Any, Optional

from app.db import get_connection, init_db, get_grants_version
from app.engine import DecisionEngine
from app.service import AccessService
from app.audit import (
    verify_ledger,
    verify_job_seals,
    record_ledger_event,
    build_job_seal_payload,
    record_security_denial,
)
from app.predicate import PredicateCompiler, compile_scope_to_sql
from app.visibility import redact_job_for_client
from app.state_machine import get_next_stage
from app.crypto import compute_job_seal, canonical_json, JOB_SEAL_KEY
from app.config import HOST, PORT
from app.auth import login, verify_session, revoke_session, verify_api_key, create_session
from app.ui import (
    render_home_page,
    render_shipments_page,
    render_queue_page,
    render_logs_page,
    render_staff_page,
    render_modern_dashboard_html,
)

# ---------------------------------------------------------------------------
# Routes that do NOT require authentication
# ---------------------------------------------------------------------------
PUBLIC_PATHS = {
    "/auth/login",
    "/auth/logout",    # logout is lenient — 401 is still fine
    "/",
    "/index.html",
    "/shipments",
    "/waiting",
    "/queue",
    "/logs",
    "/audit",
    "/staff",
    "/security",
    "/logo.jpg",
    "/logo.png",
    "/static/logo.jpg",
    "/static/logo.png",
}


class AccessRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Override to suppress default stdout spam during tests/benchmarks
        pass

    # ------------------------------------------------------------------
    # Helpers: send responses
    # ------------------------------------------------------------------
    def _send_json(self, status_code: int, data: Any):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, status_code: int, html_str: str):
        body = html_str.encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_bytes(self, status_code: int, content_type: str, data: bytes):
        self.send_response(status_code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        if content_length > 1_048_576:  # 1 MB payload limit
            return {}
        raw = self.rfile.read(content_length).decode("utf-8")
        try:
            obj = json.loads(raw)
            if not isinstance(obj, dict):
                return {}
            return obj
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Authentication: extract verified user from request headers
    # ------------------------------------------------------------------
    def _get_authenticated_user(self, conn) -> Optional[Dict[str, Any]]:
        """
        Identify the caller from verified session token or API key.
        Never trust actor_id/admin_id/grantor_id from the request body.

        Returns a user-row dict (with at least 'id', 'username', 'is_service')
        or None if the caller is unauthenticated.
        """
        auth_header = self.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
            if token:
                user = verify_session(conn, token)
                return user  # None if expired/revoked

        api_key = self.headers.get("X-Api-Key", "").strip()
        if api_key:
            user = verify_api_key(conn, api_key)
            return user  # None if invalid

        return None

    def _require_auth(self, conn) -> Optional[Dict[str, Any]]:
        """
        Enforce authentication. Sends 401 and returns None if unauthenticated.
        """
        user = self._get_authenticated_user(conn)
        if user is None:
            self._send_json(401, {
                "error": "Authentication required",
                "hint": "POST /auth/login with {username, password} to obtain a Bearer token",
            })
        return user

    def _get_demo_user(self, conn, requested_actor_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Return an active human identity for an explicitly simulated UI call."""
        actor_id = requested_actor_id or "u_asha"
        row = conn.execute(
            "SELECT id, username, is_service FROM users "
            "WHERE id = ? AND is_active = 1 AND is_service = 0",
            (actor_id,),
        ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        conn = get_connection()

        try:
            # ── 0. POST /auth/login — PUBLIC ────────────────────────────────
            if path == "/auth/login":
                body = self._read_json_body()
                username = body.get("username", "").strip()
                password = body.get("password", "")
                if not username or not password:
                    self._send_json(400, {"error": "username and password required"})
                    return
                with conn:
                    result = login(conn, username, password)
                if result is None:
                    self._send_json(401, {"error": "Invalid credentials"})
                    return
                user_id, token, expires_at = result
                self._send_json(200, {
                    "user_id": user_id,
                    "token": token,
                    "expires_at": expires_at,
                    "message": "Login successful",
                })
                return

            # ── 0b. POST /auth/logout ────────────────────────────────────────
            if path == "/auth/logout":
                auth_header = self.headers.get("Authorization", "")
                if auth_header.startswith("Bearer "):
                    token = auth_header[7:].strip()
                    revoke_session(conn, token)
                self._send_json(200, {"message": "Logged out"})
                return

            # ── All other POST routes require authentication ─────────────────
            simulation_body = self._read_json_body() if path == "/authorize" else None
            is_simulation = bool(simulation_body and simulation_body.get("simulate") is True)
            authed = self._get_authenticated_user(conn)
            if authed is None and is_simulation and not self.headers.get("Authorization"):
                authed = self._get_demo_user(conn, simulation_body.get("actor_id"))
            if authed is None:
                authed = self._require_auth(conn)
            if authed is None:
                return

            actor_id = authed["id"]

            service = AccessService(conn)
            engine = service.engine

            # ── 1. POST /authorize ───────────────────────────────────────────
            if path == "/authorize":
                body = simulation_body or {}
                action = body.get("action")
                job_id = body.get("job_id")
                job_data = body.get("job_data")
                reason = body.get("reason")
                second_approver_id = body.get("second_approver_id")

                # For simulation requests (UI simulator / explainer), evaluate the
                # actor_id supplied in the request body — this is the whole point of
                # the simulator: "what decision would user X get for action Y?".
                # The session identity (authed) still proves the caller is
                # authenticated; the body actor_id is the evaluation subject.
                if is_simulation and body.get("actor_id"):
                    eval_actor_id = body["actor_id"]
                else:
                    eval_actor_id = actor_id

                receipt = engine.authorize(
                    actor_id=eval_actor_id,
                    action=action,
                    job_id=job_id,
                    job_data=job_data,
                    reason=reason,
                    second_approver_id=second_approver_id,
                )

                if job_id and not is_simulation:
                    j_row = conn.execute("SELECT id FROM jobs WHERE id = ?", (job_id,)).fetchone()
                    if j_row:
                        with conn:
                            record_ledger_event(
                                conn,
                                event_type=f"access_{receipt['decision'].lower()}",
                                entity_type="job",
                                entity_id=job_id,
                                actor_id=actor_id,
                                details={
                                    "action": action,
                                    "decision": receipt["decision"],
                                    "code": receipt["code"],
                                    "rule": receipt["rule"],
                                },
                            )

                # Simulation responses are always HTTP 200 regardless of decision —
                # the decision (ALLOW / DENY) is carried in the JSON body.
                # Only real (non-simulated) authorizations return 403 on DENY.
                if is_simulation:
                    self._send_json(200, receipt)
                else:
                    status_code = 200 if receipt["decision"] == "ALLOW" else 403
                    self._send_json(status_code, receipt)
                return

            # ── 2. POST /grants ───────────────────────────────────────────────
            if path == "/grants":
                body = self._read_json_body()
                try:
                    # `approved_by` supplied by a caller is never approval.
                    # This endpoint only creates a durable pending proposal.
                    res = service.propose_grant(
                        user_id=body["user_id"],
                        role_name=body["role_name"],
                        scope=body.get("scope", {}),
                        effect=body.get("effect", "allow"),
                        valid_from=body.get("valid_from"),
                        valid_to=body.get("valid_to"),
                        requester_id=actor_id,
                    )
                    self._send_json(202, res)
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe), "code": "DENIED_ESCALATION_BLOCKED"})
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            if path.startswith("/grant-proposals/") and path.endswith("/approve"):
                proposal_id = path.split("/")[2]
                try:
                    res = service.approve_grant_proposal(proposal_id, actor_id, self._read_json_body().get("approve", True))
                    self._send_json(200, res)
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe)})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            # ── 3. POST /grants/{id}/revoke ───────────────────────────────────
            if path.startswith("/grants/") and path.endswith("/revoke"):
                parts = path.split("/")
                grant_id = parts[2]
                try:
                    res = service.revoke_grant(grant_id, actor_id)   # actor from session
                    self._send_json(200, res)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 4. POST /delegations ──────────────────────────────────────────
            if path == "/delegations":
                body = self._read_json_body()
                try:
                    res = service.create_delegation(
                        delegator_id=actor_id,           # from session, not body
                        delegate_id=body["delegate_id"],
                        role_name=body["role_name"],
                        scope=body.get("scope", {}),
                        reason=body.get("reason", "Operational delegation"),
                        valid_from=body.get("valid_from"),
                        valid_to=body.get("valid_to"),
                        delegation_id=body.get("id"),
                    )
                    self._send_json(201, res)
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe), "code": "DELEGATION_PROHIBITED"})
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 5. POST /breakglass ───────────────────────────────────────────
            if path == "/breakglass":
                body = self._read_json_body()
                try:
                    res = service.trigger_breakglass(
                        admin_id=actor_id,               # from session, not body
                        reason=body.get("reason", ""),
                    )
                    self._send_json(200, res)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 5b. POST /breakglass/{id}/ratify ─────────────────────────────
            if path.startswith("/breakglass/") and path.endswith("/ratify"):
                parts = path.split("/")
                bg_id = parts[2]
                try:
                    res = service.ratify_breakglass(bg_id, ratifier_id=actor_id)
                    self._send_json(200, res)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 5c. POST /roles ───────────────────────────────────────────────
            if path == "/roles":
                body = self._read_json_body()
                try:
                    res = service.create_role(
                        name=body["name"],
                        permissions=body["permissions"],
                        description=body.get("description", ""),
                        actor_id=actor_id,               # from session, not body
                    )
                    self._send_json(201, res)
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe), "code": "DENIED"})
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 6. POST /jobs (Create a job in Confirmed stage) ───────────────
            if path == "/jobs":
                body = self._read_json_body()
                receipt = engine.authorize(actor_id=actor_id, action="create", job_data=body)
                if receipt["decision"] != "ALLOW":
                    self._send_json(403, {"error": "Not authorized to create job", "receipt": receipt})
                    return

                jid = body.get(
                    "id",
                    f"J_{urllib.parse.quote(body.get('client_id', 'C01'))}_{int(conn.execute('SELECT COUNT(*) FROM jobs').fetchone()[0]) + 1}",
                )
                client_id = body["client_id"]
                branch = body["branch"]
                direction = body.get("direction", "import")
                mode = body.get("mode", "air")
                content = body.get("content", {})
                content_str = json.dumps(content)

                with conn:
                    conn.execute(
                        """
                        INSERT INTO jobs (id, client_id, branch, direction, mode, stage, content_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, 'Confirmed', ?, datetime('now'), datetime('now'))
                        """,
                        (jid, client_id, branch, direction, mode, content_str),
                    )
                    record_ledger_event(
                        conn, "job_created", "job", jid, actor_id,
                        {"client_id": client_id, "branch": branch, "stage": "Confirmed"},
                    )
                self._send_json(201, {"id": jid, "stage": "Confirmed", "status": "created"})
                return

            # ── 6b. POST /jobs/{id}/update (svc_parser: update Confirmed job) ─
            if path.startswith("/jobs/") and path.endswith("/update"):
                # Service accounts only (svc_parser)
                if not authed.get("is_service"):
                    self._send_json(403, {"error": "Only service accounts may call /jobs/{id}/update"})
                    return
                parts = path.split("/")
                job_id = parts[2]
                body = self._read_json_body()

                jrow = conn.execute("SELECT stage FROM jobs WHERE id = ?", (job_id,)).fetchone()
                if not jrow:
                    self._send_json(404, {"error": f"Job {job_id} not found"})
                    return
                if jrow["stage"] != "Confirmed":
                    self._send_json(403, {"error": "Service parser may only update Confirmed stage jobs"})
                    return

                new_content = body.get("content", {})
                with conn:
                    conn.execute(
                        "UPDATE jobs SET content_json = ?, updated_at = datetime('now') WHERE id = ?",
                        (json.dumps(new_content), job_id),
                    )
                    record_ledger_event(
                        conn, "job_updated", "job", job_id, actor_id,
                        {"stage": "Confirmed", "updated_by": actor_id},
                    )
                self._send_json(200, {"job_id": job_id, "status": "updated"})
                return

            # ── 7. POST /jobs/{id}/action ──────────────────────────────────────
            if path.startswith("/jobs/") and path.endswith("/sensitive-requests"):
                job_id = path.split("/")[2]
                body = self._read_json_body()
                try:
                    res = service.request_filed_transition(job_id, body.get("action"), body.get("reason"), actor_id)
                    self._send_json(202, res)
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe)})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path.startswith("/sensitive-requests/") and path.endswith("/approve"):
                request_id = path.split("/")[2]
                try:
                    self._send_json(200, service.approve_filed_transition(request_id, actor_id, self._read_json_body().get("approve", True)))
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe)})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path.startswith("/sensitive-requests/") and path.endswith("/execute"):
                request_id = path.split("/")[2]
                try:
                    self._send_json(200, service.execute_filed_transition(request_id, actor_id))
                except PermissionError as pe:
                    self._send_json(403, {"error": str(pe)})
                except Exception as exc:
                    self._send_json(400, {"error": str(exc)})
                return

            if path.startswith("/jobs/") and "/action" in path:
                parts = path.split("/")
                job_id = parts[2]
                body = self._read_json_body()
                action = body.get("action")
                reason = body.get("reason")
                second_approver_id = body.get("second_approver_id")

                existing = conn.execute("SELECT stage FROM jobs WHERE id=?", (job_id,)).fetchone()
                if existing and existing["stage"] == "Filed" and action in ("cancel", "reopen"):
                    self._send_json(409, {"error": "Use the persisted sensitive-request approval workflow; second_approver_id is not evidence of approval"})
                    return

                receipt = engine.authorize(
                    actor_id=actor_id,
                    action=action,
                    job_id=job_id,
                    reason=reason,
                    second_approver_id=second_approver_id,
                )
                if receipt["decision"] != "ALLOW":
                    self._send_json(403, {"error": f"Action {action} denied", "receipt": receipt})
                    return

                job_row = dict(conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone())
                current_stage = job_row["stage"]
                transition_res = get_next_stage(current_stage, action)
                if not transition_res:
                    self._send_json(400, {"error": f"No valid transition from {current_stage} for action {action}"})
                    return

                next_stage, is_sensitive = transition_res

                update_fields = ["stage = ?", "updated_at = datetime('now')"]
                params = [next_stage]

                if action == "prepare":
                    update_fields.append("prepared_by = ?")
                    params.append(actor_id)
                elif action == "check":
                    update_fields.append("checked_by = ?")
                    params.append(actor_id)
                elif action == "file":
                    update_fields.append("filed_by = ?")
                    params.append(actor_id)

                # If stage becomes Filed, calculate and record HMAC seal
                seal_hash = None
                if next_stage == "Filed":
                    sealed_job_data = dict(job_row)
                    sealed_job_data["stage"] = "Filed"
                    sealed_job_data["filed_by"] = actor_id
                    payload = build_job_seal_payload(sealed_job_data)
                    seal_hash = compute_job_seal(payload, JOB_SEAL_KEY)
                    update_fields.append("seal_hash = ?")
                    params.append(seal_hash)

                params.append(job_id)
                query = f"UPDATE jobs SET {', '.join(update_fields)} WHERE id = ?"

                with conn:
                    conn.execute(query, params)
                    if next_stage == "Filed" and seal_hash:
                        conn.execute(
                            """
                            INSERT INTO filed_job_seals (job_id, seal_hash, canonical_payload_json, filed_by, filed_at)
                            VALUES (?, ?, ?, ?, datetime('now'))
                            """,
                            (job_id, seal_hash, canonical_json(payload), actor_id),
                        )
                    record_ledger_event(
                        conn,
                        event_type=f"job_{action}",
                        entity_type="job",
                        entity_id=job_id,
                        actor_id=actor_id,
                        details={
                            "action": action,
                            "previous_stage": current_stage,
                            "new_stage": next_stage,
                            "reason": reason,
                            "second_approver_id": second_approver_id,
                            "seal_hash": seal_hash,
                        },
                    )

                self._send_json(200, {
                    "job_id": job_id,
                    "action": action,
                    "previous_stage": current_stage,
                    "new_stage": next_stage,
                    "seal_hash": seal_hash,
                    "receipt": receipt,
                })
                return

            # ── 8. POST /simulate ──────────────────────────────────────────────
            if path == "/simulate":
                body = self._read_json_body()
                try:
                    res = service.simulate_grant(
                        grantor_id=actor_id,
                        user_id=body["user_id"],
                        role_name=body["role_name"],
                        scope=body.get("scope", {}),
                    )
                    self._send_json(200, res)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            self._send_json(404, {"error": "Endpoint not found"})

        except Exception as exc:
            # Fail-closed: never expose internal errors or stack traces
            self._send_json(500, {"error": "Internal server error", "code": "INDETERMINATE"})

        finally:
            conn.close()

    # ------------------------------------------------------------------
    # GET handlers
    # ------------------------------------------------------------------
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        query_params = urllib.parse.parse_qs(parsed.query)
        accept_header = self.headers.get("Accept", "")
        is_html_request = ("text/html" in accept_header)
        is_explicit_json = (query_params.get("format", [None])[0] == "json")

        conn = get_connection()

        try:
            # ── 0. Serve Static Brand Logo — PUBLIC ──────────────────────────
            if path in ("/logo.jpg", "/logo.png", "/static/logo.jpg", "/static/logo.png"):
                logo_file = Path(__file__).parent / "static" / "logo.jpg"
                if logo_file.exists():
                    with open(logo_file, "rb") as f:
                        self._send_bytes(200, "image/jpeg", f.read())
                    return
                self._send_json(404, {"error": "Logo file not found"})
                return

            # ── 1. Home / Overview (GET / or /index.html) — PUBLIC HTML ──────
            if path == "" or path == "/index.html":
                if is_explicit_json or ("application/json" in accept_header and not is_html_request):
                    # JSON info endpoint: require auth
                    authed = self._get_authenticated_user(conn)
                    job_cnt = conn.execute("SELECT COUNT(*) FROM jobs").fetchone()[0]
                    user_cnt = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
                    policy_ver = get_grants_version(conn)
                    ledger_valid, _, ledger_msg = verify_ledger(conn)
                    self._send_json(200, {
                        "product_name": "Tez Adhikar",
                        "service": "Tez Adhikar — Access Control & Audit Service",
                        "authenticated_as": authed["id"] if authed else None,
                        "status": "healthy",
                        "database_mode": "SQLite WAL",
                        "jobs_count": job_cnt,
                        "users_count": user_cnt,
                        "policy_version": policy_ver,
                        "audit_ledger_status": "verified" if ledger_valid else "tampered",
                        "audit_ledger_message": ledger_msg,
                    })
                    return

                html = render_home_page(conn)
                self._send_html(200, html)
                return

            # ── 2. Multi-Page: Shipments Explorer — PUBLIC HTML ───────────────
            if path == "/shipments" or (path == "/jobs" and is_html_request and not is_explicit_json):
                html = render_shipments_page(conn)
                self._send_html(200, html)
                return

            # ── 3. Multi-Page: Work Queue — PUBLIC HTML ───────────────────────
            if path in ("/waiting", "/queue") or (path == "/jobs/waiting" and is_html_request and not is_explicit_json):
                html = render_queue_page(conn)
                self._send_html(200, html)
                return

            # ── 4. Multi-Page: Job Audit & Lifecycle Log — PUBLIC HTML ─────────
            if path in ("/logs", "/audit") or (path.startswith("/audit/job/") and is_html_request and not is_explicit_json):
                job_id = query_params.get("job", [None])[0]
                if not job_id and path.startswith("/audit/job/"):
                    job_id = path.split("/")[-1]
                html = render_logs_page(conn, default_job_id=job_id)
                self._send_html(200, html)
                return

            # ── 5. Multi-Page: Staff Directory — PUBLIC HTML ──────────────────
            if path == "/staff":
                html = render_staff_page(conn)
                self._send_html(200, html)
                return

            # ── 6. Legacy redirect ─────────────────────────────────────────────
            if path == "/security":
                self.send_response(302)
                self.send_header("Location", "/logs")
                self.end_headers()
                return

            # ── All remaining GET routes require authentication ────────────────
            simulated_paths = {"/explain", "/jobs/waiting"}
            is_simulation = (
                (path in simulated_paths or path.startswith("/audit/job/"))
                and query_params.get("simulate", [""])[0].lower() in ("1", "true", "demo")
            )
            requested_actor_id = query_params.get("user", [None])[0]
            authed = self._get_authenticated_user(conn)
            if authed is None and is_simulation and not self.headers.get("Authorization"):
                authed = self._get_demo_user(conn, requested_actor_id)
            if authed is None:
                authed = self._require_auth(conn)
            if authed is None:
                return

            actor_id = authed["id"]
            service = AccessService(conn)

            # ── 7. GET /explain?user=A&other=B&action=X&job=J ─────────────────
            if path == "/explain":
                user_a = query_params.get("user", [None])[0]
                user_b = query_params.get("other", [None])[0]
                action = query_params.get("action", [None])[0]
                job_id = query_params.get("job", [None])[0]
                if not (user_a and user_b and action and job_id):
                    self._send_json(400, {"error": "Missing required query parameters: user, other, action, job"})
                    return
                try:
                    exp = service.explain(user_a, user_b, action, job_id)
                    self._send_json(200, exp)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            # ── 8. GET /jobs/waiting?user=U (REST API) ────────────────────────
            if path == "/jobs/waiting":
                user_id = query_params.get("user", [None])[0]
                # If no user specified, show the authenticated user's queue.
                # The request must not authenticate as one user and inspect another user's queue
                # unless the caller is an authorized AccessAdmin.
                if not user_id:
                    user_id = actor_id
                elif user_id != actor_id:
                    admin_auth = service.engine.authorize(actor_id=actor_id, action="manage_access")
                    if admin_auth["decision"] != "ALLOW":
                        self._send_json(403, {"error": "You can only query your own waiting queue unless you are an AccessAdmin"})
                        return

                role_map = {}
                for r in conn.execute("SELECT name, permissions FROM roles WHERE is_active = 1").fetchall():
                    role_map[r["name"]] = json.loads(r["permissions"])

                engine = service.engine
                user_grants = engine._fetch_active_grants(user_id)
                user_delegations = engine._fetch_active_delegations(user_id)
                all_grants = user_grants + user_delegations

                in_mem_fn, sql_where, sql_params = PredicateCompiler.compile_waiting_for_user(
                    user_id=user_id,
                    user_grants=all_grants,
                    role_permissions_map=role_map,
                )

                # Validate pagination params
                try:
                    limit_raw = int(query_params.get("limit", [50])[0])
                    if limit_raw <= 0:
                        limit_raw = 50
                    limit = min(limit_raw, 200)
                except (ValueError, TypeError):
                    limit = 50

                count_query = f"SELECT COUNT(*) as total FROM jobs WHERE {sql_where}"
                total_count = conn.execute(count_query, sql_params).fetchone()["total"]

                list_query = f"SELECT id, client_id, branch, direction, mode, stage, prepared_by, checked_by, filed_by, created_at FROM jobs WHERE {sql_where} ORDER BY id ASC LIMIT {limit}"
                waiting_jobs = [dict(r) for r in conn.execute(list_query, sql_params).fetchall()]

                self._send_json(200, {
                    "user_id": user_id,
                    "waiting_count": total_count,
                    "returned_count": len(waiting_jobs),
                    "jobs": waiting_jobs,
                })
                return

            # ── 9. GET /jobs (REST API Keyset Pagination) ─────────────────────
            if path == "/jobs":
                # Validate limit
                try:
                    limit_raw = int(query_params.get("limit", [50])[0])
                    if limit_raw <= 0:
                        self._send_json(400, {"error": "limit must be a positive integer"})
                        return
                    limit = min(limit_raw, 200)
                except (ValueError, TypeError):
                    self._send_json(400, {"error": "limit must be an integer"})
                    return

                after = query_params.get("after", [None])[0]

                where_clauses = ["1=1"]
                params: Dict[str, Any] = {"limit": limit}

                if after:
                    where_clauses.append("id > :after")
                    params["after"] = after

                # Scope filtering: ClientViewer sees only their client's jobs.
                # Internal users see only jobs matching at least one active view grant.
                is_client_user = False
                client_scope_id = None
                u_row = conn.execute("SELECT client_id FROM users WHERE id = ?", (actor_id,)).fetchone()
                if u_row and u_row["client_id"]:
                    is_client_user = True
                    client_scope_id = u_row["client_id"]
                    where_clauses.append("client_id = :client_scope_id")
                    params["client_scope_id"] = client_scope_id
                else:
                    view_scopes = []
                    grants = service.engine._fetch_active_grants(actor_id) + service.engine._fetch_active_delegations(actor_id)
                    for grant in grants:
                        if grant.get("effect") != "allow":
                            continue
                        perms = grant.get("permissions") or []
                        if "view" in perms:
                            view_scopes.append(grant.get("scope") or {})
                    if not view_scopes:
                        where_clauses.append("1=0")
                    else:
                        view_conditions = []
                        for idx, scope in enumerate(view_scopes):
                            sub_sql, sub_params = compile_scope_to_sql(scope, prefix=f"view_{idx}")
                            view_conditions.append(f"({sub_sql})")
                            params.update(sub_params)
                        where_clauses.append("(" + " OR ".join(view_conditions) + ")")

                where_str = " AND ".join(where_clauses)
                query = (
                    f"SELECT id, client_id, branch, direction, mode, stage, prepared_by, checked_by, "
                    f"filed_by, content_json, seal_hash, created_at FROM jobs "
                    f"WHERE {where_str} ORDER BY id ASC LIMIT :limit"
                )
                rows = conn.execute(query, params).fetchall()
                jobs_out = []

                for r in rows:
                    j_dict = dict(r)
                    if is_client_user:
                        j_dict = redact_job_for_client(j_dict)
                    jobs_out.append(j_dict)

                next_after = jobs_out[-1]["id"] if jobs_out else None
                self._send_json(200, {
                    "returned_count": len(jobs_out),
                    "next_after": next_after,
                    "jobs": jobs_out,
                })
                return

            # ── 10. GET /audit/job/{id} (REST API Enriched Audit History) ─────
            if path.startswith("/audit/job/"):
                job_id = path.split("/")[-1]

                # Resolve job ID with flexible padding
                jcur = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,))
                jrow = jcur.fetchone()
                if not jrow and job_id.startswith("JOB_"):
                    num_part = job_id.replace("JOB_", "")
                    if num_part.isdigit():
                        for fmt in [f"JOB_{int(num_part):04d}", f"JOB_{int(num_part):07d}"]:
                            jcur = conn.execute("SELECT * FROM jobs WHERE id = ?", (fmt,))
                            jrow = jcur.fetchone()
                            if jrow:
                                job_id = fmt
                                break

                if not jrow:
                    self._send_json(404, {"error": "Job not found"})
                    return

                view_auth = service.engine.authorize(actor_id=actor_id, action="view", job_id=job_id)
                if view_auth["decision"] != "ALLOW":
                    self._send_json(403, {"error": "Not authorized to view this job", "receipt": view_auth})
                    return

                job_dict = dict(jrow)

                cur = conn.execute(
                    "SELECT seq, prev_hash, event_type, entity_id, actor_id, timestamp, details_json, row_hash FROM audit_ledger WHERE entity_id = ? ORDER BY seq ASC",
                    (job_id,),
                )
                events = [dict(r) for r in cur.fetchall()]

                sec_cur = conn.execute(
                    "SELECT actor_id, event_type, timestamp, details_json FROM security_events WHERE details_json LIKE ? ORDER BY id ASC",
                    (f'%"{job_id}"%',),
                )
                sec_events = []
                for sr in sec_cur.fetchall():
                    try:
                        det = json.loads(sr["details_json"])
                    except Exception:
                        det = sr["details_json"]
                    sec_events.append({
                        "actor_id": sr["actor_id"],
                        "event_type": sr["event_type"],
                        "timestamp": sr["timestamp"],
                        "details": det,
                    })

                self._send_json(200, {
                    "job_id": job_id,
                    "job": job_dict,
                    "event_count": len(events),
                    "history": events,
                    "security_incidents": sec_events,
                })
                return

            # ── 11. GET /audit/verify ──────────────────────────────────────────
            if path == "/audit/verify":
                valid, broken_seq, msg = verify_ledger(conn)
                self._send_json(200, {
                    "is_ledger_valid": valid,
                    "first_broken_seq": broken_seq,
                    "message": msg,
                })
                return

            # ── 12. GET /audit/verify-jobs ─────────────────────────────────────
            if path == "/audit/verify-jobs":
                tampered = verify_job_seals(conn)
                self._send_json(200, {
                    "tampered_count": len(tampered),
                    "is_clean": len(tampered) == 0,
                    "tampered_jobs": tampered,
                })
                return

            # ── 13. GET /users (list active users — admin only) ────────────────
            if path == "/users":
                auth_check = service.engine.authorize(actor_id=actor_id, action="manage_access")
                if auth_check["decision"] != "ALLOW":
                    self._send_json(403, {"error": "AccessAdmin role required to list users"})
                    return
                rows = conn.execute(
                    "SELECT id, username, full_name, is_service, client_id, is_active, created_at FROM users ORDER BY id"
                ).fetchall()
                self._send_json(200, {"users": [dict(r) for r in rows]})
                return

            # ── 14. GET /roles ─────────────────────────────────────────────────
            if path == "/roles":
                rows = conn.execute(
                    "SELECT name, permissions, description, is_active, created_at FROM roles ORDER BY name"
                ).fetchall()
                self._send_json(200, {"roles": [dict(r) for r in rows]})
                return

            # ── 15. GET /who-could-change?job=J&at=timestamp ──────────────────
            if path == "/who-could-change":
                job_id = query_params.get("job", [None])[0]
                at_ts = query_params.get("at", [None])[0]
                if not job_id or not at_ts:
                    self._send_json(400, {"error": "Missing required parameters: job, at"})
                    return
                try:
                    res = service.who_could_change(job_id, at_ts)
                    self._send_json(200, res)
                except Exception as e:
                    self._send_json(400, {"error": str(e)})
                return

            self._send_json(404, {"error": "Endpoint not found"})

        except Exception as exc:
            # Fail-closed
            self._send_json(500, {"error": "Internal server error", "code": "INDETERMINATE"})

        finally:
            conn.close()


def run_server(host: str = HOST, port: int = PORT):
    init_db()
    server_address = (host, port)
    httpd = HTTPServer(server_address, AccessRequestHandler)
    print(f"Tez Adhikar — Access Control & Audit Service running at http://{host}:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        httpd.server_close()


if __name__ == "__main__":
    run_server()
