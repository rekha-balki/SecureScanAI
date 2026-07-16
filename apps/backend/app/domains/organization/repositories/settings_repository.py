"""
Company settings repository (MongoDB).
"""

from datetime import UTC, datetime
from typing import Any

from app.domains.organization.domain.aggregates.company_settings import (
    CompanySettings,
    PasswordPolicySettings,
    ReportBranding,
    ScannerDefaults,
    SmtpSettings,
)
from app.platform.persistence.mongodb.collections import Collections, get_collection


def _to_document(s: CompanySettings) -> dict[str, Any]:
    return {
        "_id": s.company_id,
        "theme": s.theme,
        "smtp": {
            "host": s.smtp.host,
            "port": s.smtp.port,
            "username": s.smtp.username,
            "use_tls": s.smtp.use_tls,
            "from_address": s.smtp.from_address,
        },
        "password_policy": {
            "min_length": s.password_policy.min_length,
            "require_uppercase": s.password_policy.require_uppercase,
            "require_lowercase": s.password_policy.require_lowercase,
            "require_number": s.password_policy.require_number,
            "require_special_char": s.password_policy.require_special_char,
        },
        "session_timeout_minutes": s.session_timeout_minutes,
        "scanner_defaults": {
            "max_depth": s.scanner_defaults.max_depth,
            "max_pages": s.scanner_defaults.max_pages,
            "request_delay_ms": s.scanner_defaults.request_delay_ms,
            "enable_js_rendering": s.scanner_defaults.enable_js_rendering,
        },
        "report_branding": {
            "logo_url": s.report_branding.logo_url,
            "primary_color": s.report_branding.primary_color,
            "footer_text": s.report_branding.footer_text,
        },
        "updated_at": s.updated_at,
    }


def _to_entity(doc: dict[str, Any]) -> CompanySettings:
    smtp = doc.get("smtp", {})
    policy = doc.get("password_policy", {})
    scanner = doc.get("scanner_defaults", {})
    branding = doc.get("report_branding", {})

    return CompanySettings(
        company_id=doc["_id"],
        theme=doc.get("theme", "dark"),
        smtp=SmtpSettings(
            host=smtp.get("host"),
            port=smtp.get("port", 587),
            username=smtp.get("username"),
            use_tls=smtp.get("use_tls", True),
            from_address=smtp.get("from_address"),
        ),
        password_policy=PasswordPolicySettings(
            min_length=policy.get("min_length", 12),
            require_uppercase=policy.get("require_uppercase", True),
            require_lowercase=policy.get("require_lowercase", True),
            require_number=policy.get("require_number", True),
            require_special_char=policy.get("require_special_char", True),
        ),
        session_timeout_minutes=doc.get("session_timeout_minutes", 60),
        scanner_defaults=ScannerDefaults(
            max_depth=scanner.get("max_depth", 2),
            max_pages=scanner.get("max_pages", 25),
            request_delay_ms=scanner.get("request_delay_ms", 0),
            enable_js_rendering=scanner.get("enable_js_rendering", False),
        ),
        report_branding=ReportBranding(
            logo_url=branding.get("logo_url"),
            primary_color=branding.get("primary_color", "#22D3A6"),
            footer_text=branding.get("footer_text"),
        ),
        updated_at=doc.get("updated_at", datetime.now(UTC)),
    )


class SettingsRepository:
    """
    One settings document per company, keyed by company_id.
    """

    def __init__(self) -> None:
        self._collection = get_collection(Collections.SETTINGS)

    async def get_or_create(self, company_id: str) -> CompanySettings:
        doc = await self._collection.find_one({"_id": company_id})

        if doc is not None:
            return _to_entity(doc)

        defaults = CompanySettings(company_id=company_id)
        await self._collection.insert_one(_to_document(defaults))
        return defaults

    async def save(self, settings: CompanySettings) -> CompanySettings:
        settings.updated_at = datetime.now(UTC)
        await self._collection.replace_one(
            {"_id": settings.company_id}, _to_document(settings), upsert=True
        )
        return settings
