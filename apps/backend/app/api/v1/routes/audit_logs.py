"""
Audit log routes (FRS Section 13).
"""

from fastapi import APIRouter, Depends

from app.domains.audit.repositories.audit_log_repository import AuditLogRepository
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.platform.security.dependencies import require_roles
from app.shared.kernel.responses import ResponseBuilder

audit_logs_router = APIRouter(prefix="/audit-logs", tags=["Audit Logs"])


@audit_logs_router.get("", summary="List audit log events for the current company")
async def list_audit_logs(
    limit: int = 100,
    current_user: User = Depends(
        require_roles(
            UserRole.COMPANY_ADMIN, UserRole.PLATFORM_ADMIN, UserRole.AUDITOR
        )
    ),
):
    logs = await AuditLogRepository().list_by_company(
        current_user.company_id, limit=min(limit, 500)
    )

    return ResponseBuilder.success(
        "Audit logs retrieved.",
        [
            {
                "id": log.id,
                "user_id": log.user_id,
                "action": log.action.value,
                "target": log.target,
                "ip_address": log.ip_address,
                "result": log.result.value,
                "details": log.details,
                "timestamp": log.timestamp,
            }
            for log in logs
        ],
    )
