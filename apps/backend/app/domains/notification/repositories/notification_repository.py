"""
Notification repository (MongoDB).
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.domains.notification.domain.aggregates.notification import Notification
from app.domains.notification.domain.enums import NotificationType
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(n: Notification) -> dict[str, Any]:
    return {
        "_id": n.id,
        "company_id": n.company_id,
        "user_id": n.user_id,
        "type": n.type.value,
        "title": n.title,
        "message": n.message,
        "scan_id": n.scan_id,
        "finding_id": n.finding_id,
        "is_read": n.is_read,
        "created_at": n.created_at,
    }


def _to_entity(doc: dict[str, Any]) -> Notification:
    return Notification(
        id=doc["_id"],
        company_id=doc["company_id"],
        user_id=doc["user_id"],
        type=NotificationType(doc["type"]),
        title=doc["title"],
        message=doc["message"],
        scan_id=doc.get("scan_id"),
        finding_id=doc.get("finding_id"),
        is_read=doc.get("is_read", False),
        created_at=doc["created_at"],
    )


class NotificationRepository:
    def __init__(self) -> None:
        self._collection = get_collection(Collections.NOTIFICATIONS)

    async def create(self, notification: Notification) -> Notification:
        await self._collection.insert_one(_to_document(notification))
        return notification

    async def list_for_user(
        self, user_id: str, limit: int = 50, unread_only: bool = False
    ) -> list[Notification]:
        query: dict[str, Any] = {"user_id": user_id}
        if unread_only:
            query["is_read"] = False

        cursor = (
            self._collection.find(query).sort("created_at", -1).limit(limit)
        )
        return [_to_entity(doc) async for doc in cursor]

    async def unread_count(self, user_id: str) -> int:
        return await self._collection.count_documents(
            {"user_id": user_id, "is_read": False}
        )

    async def mark_read(self, notification_id: str, user_id: str) -> None:
        await self._collection.update_one(
            {"_id": notification_id, "user_id": user_id},
            {"$set": {"is_read": True}},
        )

    async def mark_all_read(self, user_id: str) -> None:
        await self._collection.update_many(
            {"user_id": user_id, "is_read": False},
            {"$set": {"is_read": True}},
        )

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
