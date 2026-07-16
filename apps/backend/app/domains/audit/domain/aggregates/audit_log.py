"""
Audit Log Aggregate (FRS Section 13).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.audit.domain.enums import AuditAction, AuditResult


@dataclass(slots=True)
class AuditLog:
    """
    Every Event Shall Record: Timestamp, User, Action, Target,
    IP Address, Result.
    """

    id: str

    company_id: str | None

    user_id: str | None

    action: AuditAction

    target: str | None

    ip_address: str | None

    result: AuditResult

    details: str | None = None

    timestamp: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
