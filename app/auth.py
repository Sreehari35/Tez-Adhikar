"""
Authentication module for Tez Adhikar.
Handles session-based login for human users and API key auth for service accounts.
Standard library only: secrets, hashlib, sqlite3, datetime.

Demo credentials are supplied by the operator at seed time via environment
variables. This module contains no reusable passwords or service API keys.
"""

import sqlite3
import time
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from app.crypto import hash_token, generate_session_token, verify_password, hash_api_key

# Default session duration: 8 hours
SESSION_DURATION_HOURS = 8
AUTH_RATE_LIMIT_ATTEMPTS = 5
AUTH_RATE_LIMIT_WINDOW_SECONDS = 60
_LOGIN_FAILURES: Dict[str, list[float]] = {}


def _login_allowed(username: str) -> bool:
    now = time.monotonic()
    key = username.casefold()
    attempts = [stamp for stamp in _LOGIN_FAILURES.get(key, []) if now - stamp < AUTH_RATE_LIMIT_WINDOW_SECONDS]
    _LOGIN_FAILURES[key] = attempts
    return len(attempts) < AUTH_RATE_LIMIT_ATTEMPTS


def _record_login_failure(username: str) -> None:
    _LOGIN_FAILURES.setdefault(username.casefold(), []).append(time.monotonic())


def create_session(
    conn: sqlite3.Connection,
    user_id: str,
    duration_hours: int = SESSION_DURATION_HOURS,
) -> tuple[str, str]:
    """
    Issue a new opaque random session token for the given user.
    Only the SHA-256 hash of the token is stored in the database.
    Returns: (plain_token, expires_at_iso)
    """
    token = generate_session_token()
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(hours=duration_hours)).isoformat()
    created_at = now.isoformat()

    conn.execute(
        """
        INSERT INTO sessions (token_hash, user_id, created_at, expires_at, revoked_at)
        VALUES (?, ?, ?, ?, NULL)
        """,
        (token_hash, user_id, created_at, expires_at),
    )
    return token, expires_at


def verify_session(
    conn: sqlite3.Connection,
    token: str,
) -> Optional[Dict[str, Any]]:
    """
    Verify an opaque bearer token:
    - Hashes the token and looks up the session row.
    - Checks for revocation and expiry.
    Returns the user row dict if valid, None otherwise.
    Tokens are never logged.
    """
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc).isoformat()

    cur = conn.execute(
        """
        SELECT s.token_hash, s.user_id, s.expires_at, s.revoked_at,
               u.id, u.username, u.full_name, u.is_service, u.client_id,
               u.is_active, u.password_hash, u.salt, u.api_key_hash
        FROM sessions s
        JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ?
        """,
        (token_hash,),
    )
    row = cur.fetchone()
    if not row:
        return None

    # Check revocation
    if row["revoked_at"] is not None:
        return None

    # Check expiry
    if row["expires_at"] < now:
        return None

    # Check user is still active
    if not row["is_active"]:
        return None

    return dict(row)


def revoke_session(conn: sqlite3.Connection, token: str) -> bool:
    """
    Revoke a session by its plain token. Returns True if a session was revoked.
    """
    token_hash = hash_token(token)
    now = datetime.now(timezone.utc).isoformat()
    with conn:
        cur = conn.execute(
            "UPDATE sessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL",
            (now, token_hash),
        )
    return cur.rowcount > 0


def login(
    conn: sqlite3.Connection,
    username: str,
    password: str,
) -> Optional[tuple[str, str, str]]:
    """
    Authenticate a human user with username + password.
    Returns (user_id, token, expires_at) on success, None on failure.
    Service accounts may NOT log in via password (use API key instead).
    """
    if not _login_allowed(username):
        return None
    cur = conn.execute(
        "SELECT id, password_hash, salt, is_active, is_service FROM users WHERE username = ?",
        (username,),
    )
    row = cur.fetchone()
    if not row:
        _record_login_failure(username)
        return None  # Unknown user — constant-time path continues

    # Service accounts must not use password login
    if row["is_service"]:
        _record_login_failure(username)
        return None

    if not row["is_active"]:
        _record_login_failure(username)
        return None

    if not row["password_hash"] or not row["salt"]:
        _record_login_failure(username)
        return None

    if not verify_password(password, row["password_hash"], row["salt"]):
        _record_login_failure(username)
        return None

    # Issue new session token
    token, expires_at = create_session(conn, row["id"])
    _LOGIN_FAILURES.pop(username.casefold(), None)
    return row["id"], token, expires_at


def verify_api_key(
    conn: sqlite3.Connection,
    api_key: str,
) -> Optional[Dict[str, Any]]:
    """
    Verify a service account API key.
    Hashes the key and does a single indexed lookup.
    Returns the user row dict if valid (is_service=1, is_active=1), None otherwise.
    Human users may NOT authenticate via API key.
    """
    key_hash = hash_api_key(api_key)
    cur = conn.execute(
        """
        SELECT id, username, full_name, is_service, client_id, is_active
        FROM users
        WHERE api_key_hash = ? AND is_service = 1 AND is_active = 1
        """,
        (key_hash,),
    )
    row = cur.fetchone()
    if not row:
        return None
    return dict(row)
