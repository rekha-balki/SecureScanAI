"""
Scan repository (MongoDB).
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.domains.scan.domain.aggregates.scan import Scan
from app.domains.scan.domain.enums import ScanPriority, ScanStatus, ScanType
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(scan: Scan) -> dict[str, Any]:
    return {
        "_id": scan.id,
        "company_id": scan.company_id,
        "owner_id": scan.owner_id,
        "name": scan.name,
        "target_url": scan.target_url,
        "scan_type": scan.scan_type.value,
        "curl_command": scan.curl_command,
        "description": scan.description,
        "max_depth": scan.max_depth,
        "max_pages": scan.max_pages,
        "priority": scan.priority.value,
        "status": scan.status.value,
        "pages_discovered": scan.pages_discovered,
        "pages_crawled": scan.pages_crawled,
        "plugins_executed": scan.plugins_executed,
        "findings_count": scan.findings_count,
        "error_message": scan.error_message,
        "auth_config": scan.auth_config,
        "created_at": scan.created_at,
        "updated_at": scan.updated_at,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
    }


def _to_entity(doc: dict[str, Any]) -> Scan:
    return Scan(
        id=doc["_id"],
        company_id=doc["company_id"],
        owner_id=doc["owner_id"],
        name=doc["name"],
        target_url=doc.get("target_url", ""),
        scan_type=ScanType(doc.get("scan_type", ScanType.WEB.value)),
        curl_command=doc.get("curl_command"),
        description=doc.get("description"),
        max_depth=doc.get("max_depth", 3),
        max_pages=doc.get("max_pages", 100),
        priority=ScanPriority(doc.get("priority", ScanPriority.NORMAL.value)),
        status=ScanStatus(doc.get("status", ScanStatus.DRAFT.value)),
        pages_discovered=doc.get("pages_discovered", 0),
        pages_crawled=doc.get("pages_crawled", 0),
        plugins_executed=doc.get("plugins_executed", 0),
        findings_count=doc.get("findings_count", 0),
        error_message=doc.get("error_message"),
        auth_config=doc.get("auth_config"),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
        started_at=doc.get("started_at"),
        completed_at=doc.get("completed_at"),
    )


class ScanRepository:
    """
    Persistence gateway for the Scan aggregate.
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.SCANS)

    async def create(self, scan: Scan) -> Scan:
        await self._collection.insert_one(_to_document(scan))
        return scan

    async def find_by_id(self, scan_id: str, company_id: str) -> Scan | None:
        doc = await self._collection.find_one(
            {"_id": scan_id, "company_id": company_id}
        )
        return _to_entity(doc) if doc else None

    async def list_by_company(
        self, company_id: str, limit: int = 50
    ) -> list[Scan]:
        cursor = (
            self._collection.find({"company_id": company_id})
            .sort("created_at", -1)
            .limit(limit)
        )
        return [_to_entity(doc) async for doc in cursor]

    async def update_fields(self, scan_id: str, fields: dict[str, Any]) -> None:
        fields["updated_at"] = datetime.now(UTC)
        await self._collection.update_one({"_id": scan_id}, {"$set": fields})

    async def delete_by_id(self, scan_id: str, company_id: str) -> None:
        await self._collection.delete_one(
            {"_id": scan_id, "company_id": company_id}
        )

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
