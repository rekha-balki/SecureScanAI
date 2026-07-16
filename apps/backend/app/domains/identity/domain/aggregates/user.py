"""
Identity User Aggregate.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime

from app.domains.identity.domain.enums import UserRole


@dataclass(slots=True)
class User:
    """
    Identity user aggregate root.
    """

    id: str

    first_name: str

    last_name: str

    email: str

    password_hash: str

    company_id: str

    role: UserRole = UserRole.SECURITY_ANALYST

    department: str | None = None

    designation: str | None = None

    phone: str | None = None

    mobile_number: str | None = None

    is_active: bool = True

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    @property
    def full_name(self) -> str:
        return f"{self.first_name} {self.last_name}"
