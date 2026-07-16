"""
Organization domain request/response schemas.
"""

from pydantic import BaseModel


class SmtpSettingsSchema(BaseModel):
    host: str | None = None
    port: int = 587
    username: str | None = None
    use_tls: bool = True
    from_address: str | None = None


class PasswordPolicySchema(BaseModel):
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_number: bool = True
    require_special_char: bool = True


class ScannerDefaultsSchema(BaseModel):
    max_depth: int = 2
    max_pages: int = 25
    request_delay_ms: int = 0
    enable_js_rendering: bool = False


class ReportBrandingSchema(BaseModel):
    logo_url: str | None = None
    primary_color: str = "#22D3A6"
    footer_text: str | None = None


class CompanySettingsSchema(BaseModel):
    theme: str = "dark"
    smtp: SmtpSettingsSchema = SmtpSettingsSchema()
    password_policy: PasswordPolicySchema = PasswordPolicySchema()
    session_timeout_minutes: int = 60
    scanner_defaults: ScannerDefaultsSchema = ScannerDefaultsSchema()
    report_branding: ReportBrandingSchema = ReportBrandingSchema()


class UpdateCompanySettingsRequest(CompanySettingsSchema):
    pass
