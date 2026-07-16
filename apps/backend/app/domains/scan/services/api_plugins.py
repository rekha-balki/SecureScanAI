"""
API-specific checks, evaluated against a single API response rather
than a crawled page. Built on the same PluginFinding/PluginMetadata
shapes as the web plugin framework so results flow through the same
Finding pipeline, PDF/Excel/JSON export, and compliance mapping.
"""

from __future__ import annotations

import re

from app.domains.finding.domain.enums import Confidence, Severity
from app.domains.scan.services.plugin_base import (
    PluginContext,
    PluginFinding,
    PluginMetadata,
)


class VerboseErrorDisclosurePlugin:
    metadata = PluginMetadata(
        plugin_id="api-verbose-error",
        name="Verbose Error Disclosure",
        version="1.0.0",
        category="Information Disclosure",
        description="Flags stack traces or framework error details leaked in an API response.",
        execution_priority=15,
    )

    _SIGNATURES = (
        "Traceback (most recent call last)",
        "System.Exception",
        "at java.",
        "at org.springframework",
        "Unhandled exception",
        "django.core.exceptions",
        "Fatal error:",
        "Warning: mysql_",
        "ORA-",
        "Microsoft OLE DB Provider",
        "org.hibernate",
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        body = context.response.text

        for signature in self._SIGNATURES:
            if signature in body:
                return [
                    PluginFinding(
                        category="Information Disclosure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description="The API response contains a stack trace or verbose framework error.",
                        evidence=f"Response body contains the signature: {signature!r}",
                        recommendation=(
                            "Return generic error messages to clients; log full "
                            "stack traces server-side only."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-209",
                    )
                ]

        return []


class MissingApiSecurityHeadersPlugin:
    metadata = PluginMetadata(
        plugin_id="api-security-headers",
        name="API Response Security Headers",
        version="1.0.0",
        category="HTTP Headers",
        description="Flags missing X-Content-Type-Options and an overly permissive Content-Type on API responses.",
        execution_priority=20,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        headers = {k.lower(): v for k, v in context.response.headers.items()}

        if "x-content-type-options" not in headers:
            findings.append(
                PluginFinding(
                    category="HTTP Headers",
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    description="X-Content-Type-Options header is missing on the API response.",
                    evidence="Response headers did not include 'x-content-type-options'.",
                    recommendation="Set 'X-Content-Type-Options: nosniff' on all API responses.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                )
            )

        content_type = headers.get("content-type", "")
        if content_type.startswith("text/html") and context.response.text.strip().startswith(("{", "[")):
            findings.append(
                PluginFinding(
                    category="HTTP Headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="The response body looks like JSON but is served with a text/html Content-Type.",
                    evidence=f"Content-Type: {content_type}",
                    recommendation="Serve API responses with the correct 'application/json' Content-Type.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                )
            )

        return findings


class BrokenAuthEnforcementFinding:
    """
    Not a PluginContext-based plugin - this check needs two requests
    (with and without the caller's auth), so api_scanner_service builds
    the finding directly rather than through evaluate(). Kept here for
    metadata consistency with the rest of the framework.
    """

    metadata = PluginMetadata(
        plugin_id="api-broken-auth-enforcement",
        name="Broken Authentication Enforcement",
        version="1.0.0",
        category="Authentication Indicators",
        description="Flags an endpoint that returns the same successful response with or without credentials.",
        execution_priority=10,
    )

    @classmethod
    def build_finding(cls, status_with_auth: int, status_without_auth: int) -> PluginFinding:
        return PluginFinding(
            category="Authentication Indicators",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(
                "The endpoint returned a similar successful response with the "
                "provided credentials removed, suggesting authentication is not "
                "enforced server-side."
            ),
            evidence=(
                f"With credentials: HTTP {status_with_auth}. "
                f"Without credentials: HTTP {status_without_auth}."
            ),
            recommendation=(
                "Verify this endpoint requires and validates authentication for "
                "every request; this may be a false positive if the endpoint is "
                "intentionally public."
            ),
            technical_impact="Unauthenticated users may access data or actions meant to require login.",
            owasp_reference="A07:2021 - Identification and Authentication Failures",
            cwe_reference="CWE-306",
        )


class DpdpPersonalDataExposurePlugin:
    """
    Scans an API response for patterns of Indian personal/sensitive
    personal data (as contemplated by India's Digital Personal Data
    Protection Act, 2023). Pattern matching only - this cannot confirm
    the data is real (vs. test/masked data) or whose data it is; treat
    matches as a prompt for manual review, not a confirmed breach.
    """

    metadata = PluginMetadata(
        plugin_id="dpdp-personal-data-exposure",
        name="DPDP Personal Data Exposure",
        version="1.0.0",
        category="Information Disclosure",
        description="Flags Indian personal-data patterns (Aadhaar, PAN, mobile, IFSC, passport) in API responses.",
        execution_priority=12,
    )

    _AADHAAR = re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b")
    _PAN = re.compile(r"\b[A-Z]{5}\d{4}[A-Z]\b")
    _INDIAN_MOBILE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{9}(?!\d)")
    _IFSC = re.compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b")
    _PASSPORT = re.compile(r"\b[A-PR-WYa-pr-wy][1-9]\d\s?\d{4}[1-9]\b")
    _EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if not any(t in content_type for t in ("json", "text/")):
            return []

        body = context.response.text
        categories: list[str] = []

        if self._AADHAAR.search(body):
            categories.append("Aadhaar-like 12-digit number")
        if self._PAN.search(body):
            categories.append("PAN-like identifier")
        if self._INDIAN_MOBILE.search(body):
            categories.append("Indian mobile number")
        if self._IFSC.search(body):
            categories.append("Bank IFSC code")
        if self._PASSPORT.search(body):
            categories.append("Passport-like identifier")
        if self._EMAIL.search(body):
            categories.append("Email address")

        if not categories:
            return []

        return [
            PluginFinding(
                category="Information Disclosure",
                severity=Severity.HIGH,
                confidence=Confidence.LOW,
                description=(
                    "The API response contains pattern(s) resembling Indian "
                    "personal data: " + ", ".join(categories) + "."
                ),
                evidence=(
                    "Pattern match only, not a confirmed identity - verify "
                    "manually before treating as a real data exposure."
                ),
                recommendation=(
                    "Confirm whether this endpoint should return this data to "
                    "the calling client at all (data minimization), that access "
                    "is properly authenticated and authorized, and that "
                    "transport/storage safeguards meet DPDP Section 8(5) "
                    "'reasonable security safeguards' expectations."
                ),
                business_impact=(
                    "Unnecessary or unsecured exposure of personal data as "
                    "defined under India's Digital Personal Data Protection "
                    "Act, 2023 may trigger breach-notification and security-"
                    "safeguard obligations."
                ),
                owasp_reference="A05:2021 - Security Misconfiguration",
                cwe_reference="CWE-200",
                references=[
                    "https://www.meity.gov.in/data-protection-framework",
                ],
            )
        ]


API_RESPONSE_PLUGINS: list = [
    VerboseErrorDisclosurePlugin(),
    MissingApiSecurityHeadersPlugin(),
    DpdpPersonalDataExposurePlugin(),
]
