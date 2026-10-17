"""
Cryptographic functions for Nagarkot Access Control Service.
Standard library only: hmac, hashlib, json, secrets.
"""

import hmac
import hashlib
import json
import secrets
from typing import Any, Dict, Optional
from app.config import LEDGER_HMAC_KEY, JOB_SEAL_KEY, RECEIPT_KEY

GENESIS_HASH = "0" * 64

def canonical_json(obj: Any) -> str:
    """
    Produce canonical JSON string: sorted keys, compact separators, UTF-8.
    Ensures deterministic byte representation for HMAC and hashing.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def hash_password(password: str, salt: Optional[bytes] = None) -> tuple[str, str]:
    """
    Hash password with PBKDF2-HMAC-SHA256. Returns (hex_hash, hex_salt).
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return derived.hex(), salt.hex()

def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """
    Constant-time password verification.
    """
    salt = bytes.fromhex(salt_hex)
    iterations = 100_000
    derived = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(derived.hex(), stored_hash_hex)

def hash_api_key(api_key: str) -> str:
    """
    Hash API key using SHA-256 for fast indexed lookups.
    """
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()

def hash_token(token: str) -> str:
    """
    Hash bearer session token using SHA-256.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def generate_session_token() -> str:
    """
    Generate a cryptographically secure random session token.
    """
    return secrets.token_urlsafe(32)

def compute_ledger_hash(prev_hash: str, canonical_event_str: str, key: bytes = LEDGER_HMAC_KEY) -> str:
    """
    Compute chained HMAC for audit ledger row:
    HMAC-SHA256(key, prev_hash + canonical_event)
    """
    msg = (prev_hash + canonical_event_str).encode("utf-8")
    return hmac.new(key, msg, hashlib.sha256).hexdigest()

def compute_job_seal(job_content: Dict[str, Any], key: bytes = JOB_SEAL_KEY) -> str:
    """
    Compute cryptographic HMAC seal for a Filed job.
    Includes canonical content, client, branch, direction, mode, and workflow participants.
    """
    content_str = canonical_json(job_content)
    return hmac.new(key, content_str.encode("utf-8"), hashlib.sha256).hexdigest()

def sign_decision_receipt(receipt_data: Dict[str, Any], key: bytes = RECEIPT_KEY) -> str:
    """
    Compute cryptographic signature over a decision receipt.
    """
    data_str = canonical_json(receipt_data)
    return hmac.new(key, data_str.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_receipt_signature(receipt_data: Dict[str, Any], signature: str, key: bytes = RECEIPT_KEY) -> bool:
    """
    Verify decision receipt signature with constant-time comparison.
    """
    expected = sign_decision_receipt(receipt_data, key)
    return hmac.compare_digest(expected, signature)
