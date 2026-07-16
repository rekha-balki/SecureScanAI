"""
Scan domain enums.
"""

from enum import Enum


class ScanStatus(str, Enum):
    """
    Scan lifecycle states (FRS Part 5, Section 102).
    """

    DRAFT = "draft"
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


class ScanPriority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class ScanType(str, Enum):
    """
    WEB: the existing crawl-based web application scan.
    API: a single-request scan driven by a pasted curl command,
    executed once (plus a small number of security probe variants),
    with API-specific checks and DPDP mapping.
    """

    WEB = "web"
    API = "api"
