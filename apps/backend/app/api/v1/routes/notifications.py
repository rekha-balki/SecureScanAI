"""
Notification routes (FRS Section 12).
"""

from fastapi import APIRouter, Depends

from app.domains.identity.domain.aggregates.user import User
from app.domains.notification.repositories.notification_repository import (
    NotificationRepository,
)
from app.platform.security.dependencies import get_current_user
from app.shared.kernel.responses import ResponseBuilder

notifications_router = APIRouter(prefix="/notifications", tags=["Notifications"])


@notifications_router.get("", summary="List notifications for the current user")
async def list_notifications(
    unread_only: bool = False,
    current_user: User = Depends(get_current_user),
):
    repo = NotificationRepository()

    notifications = await repo.list_for_user(
        current_user.id, unread_only=unread_only
    )
    unread_count = await repo.unread_count(current_user.id)

    return ResponseBuilder.success(
        "Notifications retrieved.",
        {
            "unread_count": unread_count,
            "items": [
                {
                    "id": n.id,
                    "type": n.type.value,
                    "title": n.title,
                    "message": n.message,
                    "scan_id": n.scan_id,
                    "finding_id": n.finding_id,
                    "is_read": n.is_read,
                    "created_at": n.created_at,
                }
                for n in notifications
            ],
        },
    )


@notifications_router.post("/{notification_id}/read", summary="Mark a notification as read")
async def mark_read(notification_id: str, current_user: User = Depends(get_current_user)):
    await NotificationRepository().mark_read(notification_id, current_user.id)
    return ResponseBuilder.success("Notification marked as read.", {"id": notification_id})


@notifications_router.post("/read-all", summary="Mark all notifications as read")
async def mark_all_read(current_user: User = Depends(get_current_user)):
    await NotificationRepository().mark_all_read(current_user.id)
    return ResponseBuilder.success("All notifications marked as read.", None)
