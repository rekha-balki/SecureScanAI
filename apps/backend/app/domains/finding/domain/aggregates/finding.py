"""
Finding Aggregate.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.finding.domain.enums import Confidence, FindingStatus, Severity


@dataclass(slots=True)
class Finding:
    """
    Finding aggregate root (FRS Part 3, Section 56).
    """

    id: str

    scan_id: str

    company_id: str

    plugin_id: str

    plugin_name: str

    category: str

    severity: Severity

    confidence: Confidence

    affected_url: str

    description: str

    evidence: str

    recommendation: str

    business_impact: str | None = None

    technical_impact: str | None = None

    references: list[str] = field(default_factory=list)

    owasp_reference: str | None = None

    cwe_reference: str | None = None

    cvss_score: float | None = None

    cvss_vector: str | None = None

    status: FindingStatus = FindingStatus.OPEN

    assigned_user_id: str | None = None

    fingerprint: str | None = None

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
