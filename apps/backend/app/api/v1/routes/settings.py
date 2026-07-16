"""
Company settings routes (FRS Section 14).
"""

import dataclasses

from fastapi import APIRouter, Depends, Request

from app.domains.audit.domain.enums import AuditAction
from app.domains.audit.services.audit_service import AuditService, client_ip
from app.domains.identity.domain.aggregates.user import User
from app.domains.identity.domain.enums import UserRole
from app.domains.organization.domain.aggregates.company_settings import (
    CompanySettings,
    PasswordPolicySettings,
    ReportBranding,
    ScannerDefaults,
    SmtpSettings,
)
from app.domains.organization.repositories.settings_repository import (
    SettingsRepository,
)
from app.domains.organization.schemas import (
    CompanySettingsSchema,
    UpdateCompanySettingsRequest,
)
from app.platform.security.dependencies import get_current_user, require_roles
from app.shared.kernel.responses import ResponseBuilder

settings_router = APIRouter(prefix="/settings", tags=["Settings"])


def _to_schema(s: CompanySettings) -> dict:
    return CompanySettingsSchema(
        theme=s.theme,
        smtp=dataclasses.asdict(s.smtp),
        password_policy=dataclasses.asdict(s.password_policy),
        session_timeout_minutes=s.session_timeout_minutes,
        scanner_defaults=dataclasses.asdict(s.scanner_defaults),
        report_branding=dataclasses.asdict(s.report_branding),
    ).model_dump()


@settings_router.get("", summary="Get company settings")
async def get_settings(current_user: User = Depends(get_current_user)):
    settings = await SettingsRepository().get_or_create(current_user.company_id)
    return ResponseBuilder.success("Settings retrieved.", _to_schema(settings))


@settings_router.put("", summary="Update company settings")
async def update_settings(
    payload: UpdateCompanySettingsRequest,
    request: Request,
    current_user: User = Depends(
        require_roles(UserRole.COMPANY_ADMIN, UserRole.PLATFORM_ADMIN)
    ),
):
    updated = CompanySettings(
        company_id=current_user.company_id,
        theme=payload.theme,
        smtp=SmtpSettings(**payload.smtp.model_dump()),
        password_policy=PasswordPolicySettings(**payload.password_policy.model_dump()),
        session_timeout_minutes=payload.session_timeout_minutes,
        scanner_defaults=ScannerDefaults(**payload.scanner_defaults.model_dump()),
        report_branding=ReportBranding(**payload.report_branding.model_dump()),
    )

    saved = await SettingsRepository().save(updated)

    await AuditService().record(
        AuditAction.SETTINGS_UPDATED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=current_user.company_id,
        ip_address=client_ip(request),
    )

    return ResponseBuilder.success("Settings updated.", _to_schema(saved))
