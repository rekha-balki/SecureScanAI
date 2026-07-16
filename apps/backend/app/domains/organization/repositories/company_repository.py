"""
Company repository (MongoDB).
"""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from app.domains.identity.domain.enums import CompanyStatus
from app.domains.organization.domain.aggregates.company import Company
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(company: Company) -> dict[str, Any]:
    return {
        "_id": company.id,
        "name": company.name,
        "industry": company.industry,
        "country": company.country,
        "address": company.address,
        "website": company.website,
        "license_type": company.license_type,
        "status": company.status.value,
        "created_at": company.created_at,
        "updated_at": company.updated_at,
    }


def _to_entity(doc: dict[str, Any]) -> Company:
    return Company(
        id=doc["_id"],
        name=doc["name"],
        industry=doc.get("industry"),
        country=doc.get("country"),
        address=doc.get("address"),
        website=doc.get("website"),
        license_type=doc.get("license_type", "trial"),
        status=CompanyStatus(doc.get("status", CompanyStatus.ACTIVE.value)),
        created_at=doc["created_at"],
        updated_at=doc["updated_at"],
    )


class CompanyRepository:
    """
    Persistence gateway for the Company aggregate.
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.COMPANIES)

    async def create(self, company: Company) -> Company:
        await self._collection.insert_one(_to_document(company))
        return company

    async def find_by_id(self, company_id: str) -> Company | None:
        doc = await self._collection.find_one({"_id": company_id})
        return _to_entity(doc) if doc else None

    async def find_by_name(self, name: str) -> Company | None:
        doc = await self._collection.find_one({"name": name})
        return _to_entity(doc) if doc else None

    async def set_status(self, company_id: str, status: CompanyStatus) -> None:
        await self._collection.update_one(
            {"_id": company_id},
            {"$set": {"status": status.value, "updated_at": datetime.now(UTC)}},
        )

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
