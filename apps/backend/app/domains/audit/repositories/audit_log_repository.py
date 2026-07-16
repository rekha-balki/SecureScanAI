"""
Audit log repository (MongoDB).
"""

from typing import Any
from uuid import uuid4

from app.domains.audit.domain.aggregates.audit_log import AuditLog
from app.domains.audit.domain.enums import AuditAction, AuditResult
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(log: AuditLog) -> dict[str, Any]:
    return {
        "_id": log.id,
        "company_id": log.company_id,
        "user_id": log.user_id,
        "action": log.action.value,
        "target": log.target,
        "ip_address": log.ip_address,
        "result": log.result.value,
        "details": log.details,
        "timestamp": log.timestamp,
    }


def _to_entity(doc: dict[str, Any]) -> AuditLog:
    return AuditLog(
        id=doc["_id"],
        company_id=doc.get("company_id"),
        user_id=doc.get("user_id"),
        action=AuditAction(doc["action"]),
        target=doc.get("target"),
        ip_address=doc.get("ip_address"),
        result=AuditResult(doc["result"]),
        details=doc.get("details"),
        timestamp=doc["timestamp"],
    )


class AuditLogRepository:
    """
    Persistence gateway for the AuditLog aggregate. Writes are
    best-effort: a logging failure must never break the request that
    triggered it (see AuditService).
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.AUDIT_LOGS)

    async def create(self, log: AuditLog) -> AuditLog:
        await self._collection.insert_one(_to_document(log))
        return log

    async def list_by_company(
        self, company_id: str, limit: int = 100
    ) -> list[AuditLog]:
        cursor = (
            self._collection.find({"company_id": company_id})
            .sort("timestamp", -1)
            .limit(limit)
        )
        return [_to_entity(doc) async for doc in cursor]

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
