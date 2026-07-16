"""
Organization (Company) Aggregate.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.identity.domain.enums import CompanyStatus


@dataclass(slots=True)
class Company:
    """
    Company aggregate root (FRS Section 4).
    """

    id: str

    name: str

    industry: str | None = None

    country: str | None = None

    address: str | None = None

    website: str | None = None

    license_type: str = "trial"

    status: CompanyStatus = CompanyStatus.ACTIVE

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
