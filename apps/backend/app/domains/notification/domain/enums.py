"""
Notification domain enums.
"""

from enum import Enum


class NotificationType(str, Enum):
    """
    System Notifications (FRS Section 12).
    """

    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_CANCELLED = "scan_cancelled"
    REPORT_READY = "report_ready"
    ASSIGNMENT = "assignment"
    FINDING_UPDATED = "finding_updated"
