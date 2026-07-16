"""
Notification service.
"""

from __future__ import annotations

from app.domains.notification.domain.aggregates.notification import Notification
from app.domains.notification.domain.enums import NotificationType
from app.domains.notification.repositories.notification_repository import (
    NotificationRepository,
)
from app.platform import get_logger

logger = get_logger(__name__)


class NotificationService:
    def __init__(self) -> None:
        self._repo = NotificationRepository()

    async def notify(
        self,
        *,
        company_id: str,
        user_id: str,
        type: NotificationType,
        title: str,
        message: str,
        scan_id: str | None = None,
        finding_id: str | None = None,
    ) -> None:
        try:
            await self._repo.create(
                Notification(
                    id=NotificationRepository.new_id(),
                    company_id=company_id,
                    user_id=user_id,
                    type=type,
                    title=title,
                    message=message,
                    scan_id=scan_id,
                    finding_id=finding_id,
                )
            )
        except Exception:  # noqa: BLE001 - notifications must not break the caller
            logger.exception("Failed to create notification type=%s", type.value)
