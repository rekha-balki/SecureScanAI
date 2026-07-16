"""
Identity User Aggregate.
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(slots=True)
class User:
    """
    Identity user aggregate root.
    """

    id: str

    username: str

    email: str

    password_hash: str

    is_active: bool = True

    created_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )

    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )