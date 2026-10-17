"""
Visibility, filtering, and data redaction rules.
Separates read visibility from execution authority.
ClientViewer sees only their client's jobs, view-only, with internal fields redacted.
"""

import json
from typing import Dict, Any, Optional

INTERNAL_REDACTED_JOB_KEYS = {
    "prepared_by",
    "checked_by",
    "filed_by",
    "assigned_to",
    "seal_hash",
}

INTERNAL_REDACTED_CONTENT_KEYS = {
    "internal_notes",
    "internal_comments",
    "margin",
    "cost_breakdown",
    "broker_margin",
    "customs_officer_notes",
}

def redact_job_for_client(job_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a sanitized, redacted version of a job for client-side users.
    Internal staff identities and internal margin/cost notes are stripped.
    """
    sanitized = {}
    for k, v in job_dict.items():
        if k in INTERNAL_REDACTED_JOB_KEYS:
            sanitized[k] = "[REDACTED]"
        elif k == "content_json":
            # Sanitize inner content
            content = v
            if isinstance(content, str):
                try:
                    content = json.loads(content)
                except Exception:
                    content = {}
            if isinstance(content, dict):
                clean_content = {
                    ck: cv for ck, cv in content.items()
                    if ck not in INTERNAL_REDACTED_CONTENT_KEYS
                }
                sanitized["content_json"] = json.dumps(clean_content)
            else:
                sanitized["content_json"] = content
        else:
            sanitized[k] = v
            
    return sanitized
