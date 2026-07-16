"""
Audit domain enums.
"""

from enum import Enum


class AuditAction(str, Enum):
    """
    Audited actions (FRS Section 13, plus FR-004, FR-018, FR-019).
    """

    USER_REGISTERED = "user_registered"
    LOGIN_SUCCESS = "login_success"
    LOGIN_FAILED = "login_failed"
    LOGOUT = "logout"
    PASSWORD_RESET_REQUESTED = "password_reset_requested"
    PASSWORD_RESET_COMPLETED = "password_reset_completed"
    USER_CREATED = "user_created"
    USER_DEACTIVATED = "user_deactivated"
    COMPANY_DEACTIVATED = "company_deactivated"
    SCAN_SUBMITTED = "scan_submitted"
    SCAN_CANCELLED = "scan_cancelled"
    SCAN_DELETED = "scan_deleted"
    SCAN_RERUN = "scan_rerun"
    FINDING_UPDATED = "finding_updated"
    SETTINGS_UPDATED = "settings_updated"


class AuditResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
