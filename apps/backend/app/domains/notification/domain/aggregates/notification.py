"""
Notification Aggregate (FRS Section 12).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.notification.domain.enums import NotificationType


@dataclass(slots=True)
class Notification:
    id: str

    company_id: str

    user_id: str

    type: NotificationType

    title: str

    message: str

    scan_id: str | None = None

    finding_id: str | None = None

    is_read: bool = False

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
