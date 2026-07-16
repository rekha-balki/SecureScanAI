"""
Password reset token repository (MongoDB).

Tokens are stored as SHA-256 hashes, never in plaintext, mirroring how
passwords themselves are stored - a database leak should not hand out
usable reset tokens.
"""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from app.platform.persistence.mongodb.collections import Collections, get_collection

_RESET_TOKEN_TTL_MINUTES = 30


class PasswordResetRepository:
    def __init__(self) -> None:
        self._collection = get_collection(Collections.PASSWORD_RESETS)

    async def create(self, user_id: str, token_hash: str) -> None:
        now = datetime.now(UTC)

        await self._collection.insert_one(
            {
                "_id": str(uuid4()),
                "user_id": user_id,
                "token_hash": token_hash,
                "created_at": now,
                "expires_at": now + timedelta(minutes=_RESET_TOKEN_TTL_MINUTES),
                "used": False,
            }
        )

    async def find_valid(self, token_hash: str) -> dict | None:
        doc = await self._collection.find_one(
            {
                "token_hash": token_hash,
                "used": False,
                "expires_at": {"$gt": datetime.now(UTC)},
            }
        )
        return doc

    async def mark_used(self, record_id: str) -> None:
        await self._collection.update_one(
            {"_id": record_id}, {"$set": {"used": True}}
        )

    async def invalidate_all_for_user(self, user_id: str) -> None:
        await self._collection.update_many(
            {"user_id": user_id, "used": False}, {"$set": {"used": True}}
        )
