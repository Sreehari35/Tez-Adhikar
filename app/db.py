"""
Database initialization, connection handling, and schema management.
SQLite in WAL mode with tuned indexes for 200,000+ jobs.
"""

import sqlite3
import json
from pathlib import Path
from typing import Optional, Any, Dict, List
from app.config import DB_PATH

def get_connection(db_path: Optional[Path] = None, timeout: float = 30.0) -> sqlite3.Connection:
    """
    Get a configured SQLite connection in WAL mode.
    """
    path = db_path or DB_PATH
    conn = sqlite3.connect(str(path), timeout=timeout)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA busy_timeout = 5000;")
    conn.execute("PRAGMA cache_size = -64000;")  # 64 MB cache
    return conn

SCHEMA_SQL = """
-- Roles table: Roles are DATA, addable without code change
CREATE TABLE IF NOT EXISTS roles (
    name TEXT PRIMARY KEY,
    permissions TEXT NOT NULL, -- JSON array of actions, e.g. ["view", "prepare"]
    description TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    full_name TEXT NOT NULL,
    password_hash TEXT,
    salt TEXT,
    api_key_hash TEXT UNIQUE,
    is_service INTEGER NOT NULL DEFAULT 0,
    client_id TEXT, -- NULL for internal staff, non-null for ClientViewer
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL
);

-- Bitemporal Grants table:
-- System time: recorded_at, closed_at (never delete, only close)
-- Business time: valid_from, valid_to
CREATE TABLE IF NOT EXISTS grants (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    role_name TEXT NOT NULL REFERENCES roles(name),
    scope_json TEXT NOT NULL DEFAULT '{}',
    effect TEXT NOT NULL CHECK(effect IN ('allow', 'deny')),
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    recorded_at TEXT NOT NULL,
    closed_at TEXT,
    created_by TEXT NOT NULL,
    approved_by TEXT
);

-- Delegations table
CREATE TABLE IF NOT EXISTS delegations (
    id TEXT PRIMARY KEY,
    delegator_id TEXT NOT NULL REFERENCES users(id),
    delegate_id TEXT NOT NULL REFERENCES users(id),
    role_name TEXT NOT NULL REFERENCES roles(name),
    scope_json TEXT NOT NULL DEFAULT '{}',
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    reason TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'revoked', 'expired')),
    created_at TEXT NOT NULL,
    created_by TEXT NOT NULL
);

-- Breakglass events table
CREATE TABLE IF NOT EXISTS breakglass (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    valid_from TEXT NOT NULL,
    valid_to TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('active', 'ratified', 'expired', 'revoked')),
    ratified_by TEXT REFERENCES users(id),
    ratified_at TEXT,
    created_at TEXT NOT NULL
);

-- Pending two-person approvals for sensitive actions (e.g. Filed job cancel/reopen)
CREATE TABLE IF NOT EXISTS pending_approvals (
    id TEXT PRIMARY KEY,
    job_id TEXT NOT NULL,
    action TEXT NOT NULL CHECK(action IN ('cancel', 'reopen')),
    requested_by TEXT NOT NULL REFERENCES users(id),
    reason TEXT NOT NULL,
    approved_by TEXT REFERENCES users(id),
    expected_stage TEXT NOT NULL DEFAULT 'Filed',
    expires_at TEXT NOT NULL,
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'executed', 'expired')),
    created_at TEXT NOT NULL,
    completed_at TEXT
);

-- Immutable proposals for administrative changes.  A request is not a grant;
-- it only becomes effective after a separately authenticated administrator
-- approves this exact stored payload.
CREATE TABLE IF NOT EXISTS admin_proposals (
    id TEXT PRIMARY KEY,
    operation TEXT NOT NULL CHECK(operation IN ('grant_create')),
    payload_json TEXT NOT NULL,
    requested_by TEXT NOT NULL REFERENCES users(id),
    approved_by TEXT REFERENCES users(id),
    status TEXT NOT NULL CHECK(status IN ('pending', 'approved', 'rejected', 'expired')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);

-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    branch TEXT NOT NULL,
    direction TEXT NOT NULL CHECK(direction IN ('import', 'export')),
    mode TEXT NOT NULL CHECK(mode IN ('air', 'fcl', 'lcl')),
    stage TEXT NOT NULL CHECK(stage IN ('Confirmed', 'Prepared', 'Checked', 'Filed', 'Cancelled', 'Reopened')),
    prepared_by TEXT REFERENCES users(id),
    checked_by TEXT REFERENCES users(id),
    filed_by TEXT REFERENCES users(id),
    assigned_to TEXT REFERENCES users(id),
    content_json TEXT NOT NULL DEFAULT '{}',
    seal_hash TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- Cryptographic Audit Ledger: append-only with HMAC chaining
CREATE TABLE IF NOT EXISTS audit_ledger (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    prev_hash TEXT NOT NULL,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details_json TEXT NOT NULL,
    row_hash TEXT NOT NULL
);

-- Policy metadata (version counter to avoid stale cache)
CREATE TABLE IF NOT EXISTS policy_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Security tracking for probe detection (denials)
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    timestamp REAL NOT NULL,
    details_json TEXT NOT NULL
);

-- Active sessions for authenticated users (tokens stored as SHA-256 hashes only)
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT
);

-- Durable, immutable filed declaration seal registry
CREATE TABLE IF NOT EXISTS filed_job_seals (
    cycle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id TEXT NOT NULL,
    seal_hash TEXT NOT NULL,
    canonical_payload_json TEXT NOT NULL,
    filed_by TEXT NOT NULL REFERENCES users(id),
    filed_at TEXT NOT NULL
);

-- High-performance indexes
CREATE INDEX IF NOT EXISTS idx_jobs_stage_assigned ON jobs(stage, assigned_to);
CREATE INDEX IF NOT EXISTS idx_jobs_filter ON jobs(stage, client_id, branch, direction, mode, id);
CREATE INDEX IF NOT EXISTS idx_jobs_prepared_by ON jobs(prepared_by);
CREATE INDEX IF NOT EXISTS idx_grants_user_active ON grants(user_id, closed_at, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_grants_time_travel ON grants(recorded_at, closed_at, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_delegations_active ON delegations(delegate_id, status, valid_from, valid_to);
CREATE INDEX IF NOT EXISTS idx_ledger_entity ON audit_ledger(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_security_actor_time ON security_events(actor_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at, revoked_at);
CREATE INDEX IF NOT EXISTS idx_filed_job_seals_job_cycle ON filed_job_seals(job_id, cycle_id);
CREATE INDEX IF NOT EXISTS idx_pending_approvals_job ON pending_approvals(job_id, status);
CREATE INDEX IF NOT EXISTS idx_admin_proposals_status ON admin_proposals(status, expires_at);
"""

# Default standard role definitions
DEFAULT_ROLES = [
    {
        "name": "Maker",
        "permissions": ["view", "create", "prepare", "cancel"],
        "description": "Prepares job documents and checklists from Confirmed stage",
    },
    {
        "name": "Checker",
        "permissions": ["view", "check"],
        "description": "Reviews and approves prepared jobs (cannot be the preparer)",
    },
    {
        "name": "Filer",
        "permissions": ["view", "file"],
        "description": "Files checked customs jobs with authorities (cannot be the preparer)",
    },
    {
        "name": "Supervisor",
        "permissions": ["view", "create", "update", "prepare", "check", "file", "cancel", "reopen"],
        "description": "Senior branch staff: can act across pipeline, delegate authority, request/approve filed job overrides",
    },
    {
        "name": "Viewer",
        "permissions": ["view"],
        "description": "Internal staff read-only access within branch/client scope",
    },
    {
        "name": "ClientViewer",
        "permissions": ["view"],
        "description": "External client user: view-only for their own client's shipments, internal fields redacted",
    },
    {
        "name": "AccessAdmin",
        "permissions": ["manage_access"],
        "description": "Manages roles, grants and delegations; strictly forbidden from job pipeline actions",
    },
    {
        "name": "Auditor",
        "permissions": ["view"],
        "description": "Compliance auditor: read-only access to all jobs, ledger, and time-machine verification",
    },
    {
        "name": "Service",
        "permissions": ["create", "update"],
        "description": "Automated services (e.g. overnight EDI parser); restricted to Confirmed stage jobs only",
    },
]

def init_db(db_path: Optional[Path] = None) -> None:
    """
    Initialize database schema, indexes, and default roles and policy counter.
    """
    path = db_path or DB_PATH
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = get_connection(path)
    with conn:
        conn.executescript(SCHEMA_SQL)
        # Initialize policy version counter
        conn.execute(
            "INSERT OR IGNORE INTO policy_metadata (key, value) VALUES ('grants_version', '1')"
        )
        # Seed default roles
        for role in DEFAULT_ROLES:
            conn.execute(
                """
                INSERT OR IGNORE INTO roles (name, permissions, description, is_active, created_at)
                VALUES (?, ?, ?, 1, datetime('now'))
                """,
                (role["name"], json.dumps(role["permissions"]), role["description"]),
            )
    conn.close()

def get_grants_version(conn: sqlite3.Connection) -> int:
    cur = conn.execute("SELECT value FROM policy_metadata WHERE key = 'grants_version'")
    row = cur.fetchone()
    return int(row["value"]) if row else 1

def increment_grants_version(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "UPDATE policy_metadata SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'grants_version' RETURNING value"
    )
    row = cur.fetchone()
    return int(row["value"]) if row else 1
