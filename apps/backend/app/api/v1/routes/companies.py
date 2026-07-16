"""
Company management routes (FRS Section 4).
"""

from fastapi import APIRouter, Depends, Request

from app.domains.audit.domain.enums import AuditAction
from app.domains.audit.services.audit_service import AuditService, client_ip
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import CompanyStatus, UserRole
from app.domains.organization.repositories.company_repository import (
    CompanyRepository,
)
from app.platform.errors.exceptions import ResourceNotFoundException
from app.platform.security.dependencies import get_current_user, require_roles
from app.shared.kernel.responses import ResponseBuilder

companies_router = APIRouter(prefix="/companies", tags=["Companies"])


@companies_router.get("/me", summary="Get the current company")
async def get_my_company(current_user: User = Depends(get_current_user)):
    repo = CompanyRepository()

    company = await repo.find_by_id(current_user.company_id)

    if company is None:
        raise ResourceNotFoundException("Company not found.")

    return ResponseBuilder.success(
        "Company retrieved.",
        {
            "id": company.id,
            "name": company.name,
            "industry": company.industry,
            "country": company.country,
            "address": company.address,
            "website": company.website,
            "license_type": company.license_type,
            "status": company.status.value,
            "created_at": company.created_at,
        },
    )


@companies_router.post("/{company_id}/deactivate", summary="Deactivate a company")
async def deactivate_company(
    company_id: str,
    request: Request,
    current_user: User = Depends(require_roles(UserRole.PLATFORM_ADMIN)),
):
    repo = CompanyRepository()

    await repo.set_status(company_id, CompanyStatus.DISABLED)

    await AuditService().record(
        AuditAction.COMPANY_DEACTIVATED,
        user_id=current_user.id,
        target=company_id,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("Company deactivated.", {"id": company_id})
