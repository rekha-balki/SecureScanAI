"""
Attack surface repository (MongoDB).

Stores the raw inventory of URLs, query parameters, and forms
discovered during a scan's crawl (FRS Section 24: Discovery Engine
output), independent of whether any finding was raised against them.
One document per scan.
"""

from datetime import UTC, datetime
from typing import Any

from app.platform.persistence.mongodb.collections import Collections, get_collection


class AttackSurfaceRepository:
    def __init__(self) -> None:
        self._collection = get_collection(Collections.ATTACK_SURFACE)

    async def save(
        self,
        scan_id: str,
        company_id: str,
        urls: list[dict[str, Any]],
        parameters: list[dict[str, Any]],
        forms: list[dict[str, Any]],
    ) -> None:
        await self._collection.replace_one(
            {"_id": scan_id},
            {
                "_id": scan_id,
                "company_id": company_id,
                "urls": urls,
                "parameters": parameters,
                "forms": forms,
                "created_at": datetime.now(UTC),
            },
            upsert=True,
        )

    async def find_by_scan(self, scan_id: str, company_id: str) -> dict | None:
        return await self._collection.find_one(
            {"_id": scan_id, "company_id": company_id}
        )
