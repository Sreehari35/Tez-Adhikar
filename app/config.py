"""
Configuration module for Nagarkot Access Control Service.
Standard library only.
"""

import os
import sqlite3
from pathlib import Path

# Base Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.environ.get("NAGARKOT_DATA_DIR", BASE_DIR / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# Database
DB_PATH = Path(os.environ.get("NAGARKOT_DB_PATH", DATA_DIR / "access_control.db"))

# Security Keys
# Ledger HMAC key must come from an environment variable or secure keyfile, never hard-coded.
LEDGER_KEY_FILE = DATA_DIR / ".ledger_key"
JOB_SEAL_KEY_FILE = DATA_DIR / ".job_seal_key"
RECEIPT_KEY_FILE = DATA_DIR / ".receipt_key"


def _database_has_signed_history(db_path: Path) -> bool:
    """Return True if a database already contains immutable signed history."""
    if not db_path.exists():
        return False
    try:
        with sqlite3.connect(str(db_path)) as conn:
            tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            if "audit_ledger" in tables:
                count = conn.execute("SELECT COUNT(*) FROM audit_ledger").fetchone()[0]
                if count > 0:
                    return True
            if "filed_job_seals" in tables:
                count = conn.execute("SELECT COUNT(*) FROM filed_job_seals").fetchone()[0]
                if count > 0:
                    return True
    except Exception:
        return False
    return False


def _get_or_create_key(env_var_name: str, key_file_path: Path, default_bytes_len: int = 32) -> bytes:
    env_val = os.environ.get(env_var_name)
    if env_val:
        return env_val.encode("utf-8")
    if key_file_path.exists():
        return key_file_path.read_bytes().strip()

    if _database_has_signed_history(DB_PATH):
        raise RuntimeError(
            f"Missing signing key for {env_var_name}. Existing signed database state detected; "
            "set the environment variable or provide the matching key file before starting the service."
        )

    # Generate a cryptographically secure random key only for new databases.
    new_key = os.urandom(default_bytes_len).hex().encode("utf-8")
    try:
        key_file_path.write_bytes(new_key)
    except Exception:
        pass
    return new_key

LEDGER_HMAC_KEY = _get_or_create_key("NAGARKOT_LEDGER_KEY", LEDGER_KEY_FILE)
JOB_SEAL_KEY = _get_or_create_key("NAGARKOT_JOB_SEAL_KEY", JOB_SEAL_KEY_FILE)
RECEIPT_KEY = _get_or_create_key("NAGARKOT_RECEIPT_KEY", RECEIPT_KEY_FILE)

# Server Config
HOST = os.environ.get("NAGARKOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("NAGARKOT_PORT", "8000"))

# Thresholds & Limits
PROBE_THRESHOLD_COUNT = 5     # Denials within window that trigger ANOMALY
PROBE_WINDOW_SECONDS = 300   # 5 minutes
BREAKGLASS_DURATION_MINUTES = 30
AUTH_RATE_LIMIT_ATTEMPTS = 5
AUTH_RATE_LIMIT_WINDOW_SECONDS = 60
