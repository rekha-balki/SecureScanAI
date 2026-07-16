"""
Finding repository (MongoDB).
"""

from typing import Any
from uuid import uuid4

from app.domains.finding.domain.aggregates.finding import Finding
from app.domains.finding.domain.enums import Confidence, FindingStatus, Severity
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(finding: Finding) -> dict[str, Any]:
    return {
        "_id": finding.id,
        "scan_id": finding.scan_id,
        "company_id": finding.company_id,
        "plugin_id": finding.plugin_id,
        "plugin_name": finding.plugin_name,
        "category": finding.category,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "affected_url": finding.affected_url,
        "description": finding.description,
        "evidence": finding.evidence,
        "recommendation": finding.recommendation,
        "business_impact": finding.business_impact,
        "technical_impact": finding.technical_impact,
        "references": finding.references,
        "owasp_reference": finding.owasp_reference,
        "cwe_reference": finding.cwe_reference,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "status": finding.status.value,
        "assigned_user_id": finding.assigned_user_id,
        "fingerprint": finding.fingerprint,
        "created_at": finding.created_at,
    }


def _to_entity(doc: dict[str, Any]) -> Finding:
    return Finding(
        id=doc["_id"],
        scan_id=doc["scan_id"],
        company_id=doc["company_id"],
        plugin_id=doc["plugin_id"],
        plugin_name=doc["plugin_name"],
        category=doc["category"],
        severity=Severity(doc["severity"]),
        confidence=Confidence(doc["confidence"]),
        affected_url=doc["affected_url"],
        description=doc["description"],
        evidence=doc["evidence"],
        recommendation=doc["recommendation"],
        business_impact=doc.get("business_impact"),
        technical_impact=doc.get("technical_impact"),
        references=doc.get("references", []),
        owasp_reference=doc.get("owasp_reference"),
        cwe_reference=doc.get("cwe_reference"),
        cvss_score=doc.get("cvss_score"),
        cvss_vector=doc.get("cvss_vector"),
        status=FindingStatus(doc.get("status", FindingStatus.OPEN.value)),
        assigned_user_id=doc.get("assigned_user_id"),
        fingerprint=doc.get("fingerprint"),
        created_at=doc["created_at"],
    )


class FindingRepository:
    """
    Persistence gateway for the Finding aggregate.
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.FINDINGS)

    async def bulk_create(self, findings: list[Finding]) -> None:
        if not findings:
            return
        await self._collection.insert_many([_to_document(f) for f in findings])

    async def list_by_scan(self, scan_id: str, company_id: str) -> list[Finding]:
        cursor = self._collection.find(
            {"scan_id": scan_id, "company_id": company_id}
        ).sort("severity", 1)
        return [_to_entity(doc) async for doc in cursor]

    async def exists_by_fingerprint(self, scan_id: str, fingerprint: str) -> bool:
        doc = await self._collection.find_one(
            {"scan_id": scan_id, "fingerprint": fingerprint}
        )
        return doc is not None

    async def delete_by_scan(self, scan_id: str, company_id: str) -> None:
        await self._collection.delete_many(
            {"scan_id": scan_id, "company_id": company_id}
        )

    async def find_by_id(self, finding_id: str, company_id: str) -> Finding | None:
        doc = await self._collection.find_one(
            {"_id": finding_id, "company_id": company_id}
        )
        return _to_entity(doc) if doc else None

    async def update_status_and_assignee(
        self,
        finding_id: str,
        company_id: str,
        status: FindingStatus | None,
        assigned_user_id: str | None,
    ) -> None:
        fields: dict[str, Any] = {}
        if status is not None:
            fields["status"] = status.value
        if assigned_user_id is not None:
            fields["assigned_user_id"] = assigned_user_id

        if fields:
            await self._collection.update_one(
                {"_id": finding_id, "company_id": company_id}, {"$set": fields}
            )

    @staticmethod
    def new_id() -> str:
        return str(uuid4())
