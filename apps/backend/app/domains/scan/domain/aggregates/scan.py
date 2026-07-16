"""
Scan Aggregate.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.scan.domain.enums import ScanPriority, ScanStatus, ScanType


@dataclass(slots=True)
class Scan:
    """
    Scan aggregate root (FRS Part 2 & Part 5).
    """

    id: str

    company_id: str

    owner_id: str

    name: str

    target_url: str = ""

    scan_type: ScanType = ScanType.WEB

    # Only set when scan_type is API - the raw curl command the user
    # provided, parsed at execution time by curl_parser.py.
    curl_command: str | None = None

    description: str | None = None

    max_depth: int = 3

    max_pages: int = 100

    priority: ScanPriority = ScanPriority.NORMAL

    status: ScanStatus = ScanStatus.DRAFT

    pages_discovered: int = 0

    pages_crawled: int = 0

    plugins_executed: int = 0

    findings_count: int = 0

    error_message: str | None = None

    # Optional authentication profile (FRS Section 29). Stored as a
    # plain dict rather than a nested dataclass to keep persistence
    # simple; see AuthConfigSchema for the shape. NOTE: credentials are
    # currently stored in cleartext in MongoDB - acceptable for this
    # pass, but should move to an encrypted-at-rest secret store before
    # any production use.
    auth_config: dict | None = None

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    started_at: datetime | None = None

    completed_at: datetime | None = None
