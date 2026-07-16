"""
Company Settings Aggregate (FRS Section 14).
"""

from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(slots=True)
class SmtpSettings:
    host: str | None = None
    port: int = 587
    username: str | None = None
    use_tls: bool = True
    from_address: str | None = None


@dataclass(slots=True)
class PasswordPolicySettings:
    min_length: int = 12
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_number: bool = True
    require_special_char: bool = True


@dataclass(slots=True)
class ScannerDefaults:
    max_depth: int = 2
    max_pages: int = 25
    request_delay_ms: int = 0
    # Opt-in JS-rendered link discovery via a headless browser
    # (Playwright). Requires `pip install playwright && playwright
    # install chromium` on the host running the backend - see README.
    # Left off by default: it adds real latency and a new runtime
    # dependency, and this code path has not been exercised against a
    # live browser in this environment.
    enable_js_rendering: bool = False


@dataclass(slots=True)
class ReportBranding:
    logo_url: str | None = None
    primary_color: str = "#22D3A6"
    footer_text: str | None = None


@dataclass(slots=True)
class CompanySettings:
    company_id: str

    theme: str = "dark"

    smtp: SmtpSettings = field(default_factory=SmtpSettings)

    password_policy: PasswordPolicySettings = field(
        default_factory=PasswordPolicySettings
    )

    session_timeout_minutes: int = 60

    scanner_defaults: ScannerDefaults = field(default_factory=ScannerDefaults)

    report_branding: ReportBranding = field(default_factory=ReportBranding)

    updated_at: datetime = field(
        default_factory=lambda: datetime.now(UTC)
    )
