"""
Customs job lifecycle state machine and transition validation.
Stages: Confirmed -> Prepared -> Checked -> Filed; also Cancelled and Reopened.
"""

from typing import Tuple, Optional

STAGES = ("Confirmed", "Prepared", "Checked", "Filed", "Cancelled", "Reopened")

ACTIONS = (
    "view",
    "create",
    "update",
    "prepare",
    "check",
    "file",
    "cancel",
    "reopen",
    "manage_access",
)

# Target stage resulting from an action
TRANSITIONS = {
    # (current_stage, action) -> (next_stage, is_sensitive)
    ("Confirmed", "prepare"): ("Prepared", False),
    ("Reopened", "prepare"): ("Prepared", False),
    ("Prepared", "check"): ("Checked", False),
    ("Checked", "file"): ("Filed", False),
    
    # Cancellations
    ("Confirmed", "cancel"): ("Cancelled", False),
    ("Prepared", "cancel"): ("Cancelled", False),
    ("Checked", "cancel"): ("Cancelled", False),
    ("Reopened", "cancel"): ("Cancelled", False),
    ("Filed", "cancel"): ("Cancelled", True),  # Sensitive: requires Supervisor + reason + 2nd approver
    
    # Reopens
    ("Cancelled", "reopen"): ("Reopened", False),
    ("Filed", "reopen"): ("Reopened", True),   # Sensitive: requires Supervisor + reason + 2nd approver
}

# Stages in which a job content can be updated
EDITABLE_STAGES = {"Confirmed", "Prepared", "Checked", "Reopened"}

def get_next_stage(current_stage: str, action: str) -> Optional[Tuple[str, bool]]:
    """
    Returns (next_stage, is_sensitive) if valid transition, or None if invalid.
    """
    return TRANSITIONS.get((current_stage, action))

def is_transition_legal(current_stage: str, action: str) -> bool:
    """
    Check if an action is valid for the job's current stage according to state machine.
    """
    if action == "view":
        return True
    if action == "update":
        return current_stage in EDITABLE_STAGES
    if action == "create":
        return True
    return (current_stage, action) in TRANSITIONS
