"""
Scan domain request/response schemas.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, model_validator

from app.domains.scan.domain.enums import ScanPriority, ScanStatus, ScanType


class AuthType(str, Enum):
    NONE = "none"
    BEARER = "bearer"
    COOKIE = "cookie"
    FORM = "form"


class AuthConfigSchema(BaseModel):
    """
    Authentication profile for a scan (FRS Section 29).

    - bearer: sends `Authorization: Bearer {bearer_token}` on every request.
    - cookie: seeds the crawl session with the given cookie name/value pairs.
    - form: performs one POST to `login_url` with the given field names/
      values before crawling, and reuses whatever session cookies that
      login response sets for the rest of the scan.
    """

    type: AuthType = AuthType.NONE
    bearer_token: str | None = None
    cookies: dict[str, str] | None = None
    login_url: str | None = None
    username_field: str | None = None
    username: str | None = None
    password_field: str | None = None
    password: str | None = None
    extra_fields: dict[str, str] | None = None


class CreateScanRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    scan_type: ScanType = ScanType.WEB
    target_url: str | None = None
    curl_command: str | None = None
    description: str | None = None
    max_depth: int = Field(default=2, ge=0, le=10)
    max_pages: int = Field(default=25, ge=1, le=500)
    priority: ScanPriority = ScanPriority.NORMAL
    auth_config: AuthConfigSchema | None = None

    @model_validator(mode="after")
    def _validate_required_fields(self) -> "CreateScanRequest":
        if self.scan_type == ScanType.WEB and not self.target_url:
            raise ValueError("target_url is required for a web scan.")
        if self.scan_type == ScanType.API and not self.curl_command:
            raise ValueError("curl_command is required for an API scan.")
        return self


class ScanResponse(BaseModel):
    id: str
    name: str
    scan_type: ScanType
    target_url: str
    description: str | None
    status: ScanStatus
    priority: ScanPriority
    max_depth: int
    max_pages: int
    pages_discovered: int
    pages_crawled: int
    plugins_executed: int
    findings_count: int
    error_message: str | None
    has_auth: bool = False
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None


class FindingResponse(BaseModel):
    id: str
    scan_id: str
    plugin_id: str
    plugin_name: str
    category: str
    severity: str
    confidence: str
    affected_url: str
    description: str
    evidence: str
    recommendation: str
    business_impact: str | None
    technical_impact: str | None
    owasp_reference: str | None
    cwe_reference: str | None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    status: str
    assigned_user_id: str | None = None
    created_at: datetime


class UpdateFindingRequest(BaseModel):
    status: str | None = None
    assigned_user_id: str | None = None
