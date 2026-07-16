"""
Audit logging service.

Provides a single entry point (`record`) used across every domain so
that "critical actions" (FRS Section 17 acceptance criteria) are
captured consistently. Failures to write an audit record are logged
and swallowed - auditing must never break the user-facing request.
"""

from __future__ import annotations

from app.domains.audit.domain.aggregates.audit_log import AuditLog
from app.domains.audit.domain.enums import AuditAction, AuditResult
from app.domains.audit.repositories.audit_log_repository import AuditLogRepository
from app.platform import get_logger

logger = get_logger(__name__)


class AuditService:
    def __init__(self) -> None:
        self._repo = AuditLogRepository()

    async def record(
        self,
        action: AuditAction,
        *,
        company_id: str | None = None,
        user_id: str | None = None,
        target: str | None = None,
        ip_address: str | None = None,
        result: AuditResult = AuditResult.SUCCESS,
        details: str | None = None,
    ) -> None:
        try:
            await self._repo.create(
                AuditLog(
                    id=AuditLogRepository.new_id(),
                    company_id=company_id,
                    user_id=user_id,
                    action=action,
                    target=target,
                    ip_address=ip_address,
                    result=result,
                    details=details,
                )
            )
        except Exception:  # noqa: BLE001 - auditing must never break the request
            logger.exception("Failed to write audit log for action=%s", action.value)


def client_ip(request) -> str | None:
    """
    Best-effort client IP extraction, honoring a trusted X-Forwarded-For
    when present (e.g. behind a reverse proxy / load balancer).
    """

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()

    return request.client.host if request.client else None
