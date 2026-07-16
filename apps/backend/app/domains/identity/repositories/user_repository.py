"""
User repository (MongoDB).
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(user: User) -> dict[str, Any]:
    return {
        "_id": user.id,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "password_hash": user.password_hash,
        "company_id": user.company_id,
        "role": user.role.value,
        "department": user.department,
        "designation": user.designation,
        "phone": user.phone,
        "mobile_number": user.mobile_number,
        "is_active": user.is_active,
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


def _to_entity(doc: dict[str, Any]) -> User:
    return User(
        id=doc["_id"],
        first_name=doc["first_name"],
        last_name=doc["last_name"],
        email=doc["email"],
        password_hash=doc["password_hash"],
        company_id=doc["company_id"],
        role=UserRole(doc.get("role", UserRole.SECURITY_ANALYST.value)),
        department=doc.get("department"),
        designation=doc.get("designation"),
        phone=doc.get("phone"),
        mobile_number=doc.get("mobile_number"),
        is_active=doc.get("is_active", True),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
    )


class UserRepository:
    """
    Persistence gateway for the User aggregate.
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.USERS)

    async def create(self, user: User) -> User:
        await self._collection.insert_one(_to_document(user))
        return user

    async def find_by_id(self, user_id: str) -> User | None:
        doc = await self._collection.find_one({"_id": user_id})
        return _to_entity(doc) if doc else None

    async def find_by_email(self, email: str) -> User | None:
        doc = await self._collection.find_one({"email": email.lower()})
        return _to_entity(doc) if doc else None

    async def list_by_company(self, company_id: str) -> list[User]:
        cursor = self._collection.find({"company_id": company_id})
        return [_to_entity(doc) async for doc in cursor]

    async def set_active(self, user_id: str, is_active: bool) -> None:
        await self._collection.update_one(
            {"_id": user_id},
            {"$set": {"is_active": is_active, "updated_at": datetime.now(UTC)}},
        )

    async def update_password(self, user_id: str, password_hash: str) -> None:
        await self._collection.update_one(
            {"_id": user_id},
            {
                "$set": {
                    "password_hash": password_hash,
                    "updated_at": datetime.now(UTC),
                }
            },
        )

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
