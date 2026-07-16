"""
Built-in vulnerability plugins (FRS Part 3, Section 65).

Each plugin is a small, independent, side-effect-free class that
implements the VulnerabilityPlugin protocol. Plugins never share
mutable state and a failure in one plugin must never affect others
(isolation is enforced by the PluginEngine, not by the plugins
themselves).
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

from app.domains.finding.domain.enums import Confidence, Severity
from app.domains.scan.services.plugin_base import (
    PluginContext,
    PluginFinding,
    PluginMetadata,
)


class SecurityHeadersPlugin:
    metadata = PluginMetadata(
        plugin_id="security-headers",
        name="Security Headers",
        version="1.0.0",
        category="HTTP Headers",
        description="Checks for the presence of standard security headers.",
        execution_priority=20,
    )

    _REQUIRED = {
        "x-content-type-options": (
            "X-Content-Type-Options header is missing.",
            "Prevents MIME-type sniffing attacks.",
            "Set 'X-Content-Type-Options: nosniff' on all responses.",
            Severity.LOW,
        ),
        "x-frame-options": (
            "X-Frame-Options header is missing.",
            "Increases exposure to clickjacking attacks.",
            "Set 'X-Frame-Options: DENY' or use a CSP frame-ancestors directive.",
            Severity.MEDIUM,
        ),
        "content-security-policy": (
            "Content-Security-Policy header is missing.",
            "Reduces defense-in-depth against XSS and data-injection attacks.",
            "Define a restrictive Content-Security-Policy for the application.",
            Severity.MEDIUM,
        ),
        "referrer-policy": (
            "Referrer-Policy header is missing.",
            "May leak full URLs, including sensitive query parameters, to third parties.",
            "Set 'Referrer-Policy: strict-origin-when-cross-origin' or stricter.",
            Severity.LOW,
        ),
        "permissions-policy": (
            "Permissions-Policy header is missing.",
            "Browser features (camera, geolocation, etc.) are not explicitly restricted.",
            "Define a Permissions-Policy restricting unused browser features.",
            Severity.INFORMATIONAL,
        ),
    }

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        headers = {k.lower(): v for k, v in context.response.headers.items()}

        for header, (desc, impact, rec, severity) in self._REQUIRED.items():
            if header not in headers:
                findings.append(
                    PluginFinding(
                        category="HTTP Headers",
                        severity=severity,
                        confidence=Confidence.HIGH,
                        description=desc,
                        evidence=f"Response headers did not include '{header}'.",
                        recommendation=rec,
                        technical_impact=impact,
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        references=["https://owasp.org/www-project-secure-headers/"],
                    )
                )

        return findings


class HstsPlugin:
    metadata = PluginMetadata(
        plugin_id="hsts",
        name="HSTS",
        version="1.0.0",
        category="Transport Security",
        description="Checks for HTTP Strict-Transport-Security enforcement.",
        execution_priority=10,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        if not context.is_https:
            return []

        headers = {k.lower(): v for k, v in context.response.headers.items()}

        if "strict-transport-security" not in headers:
            return [
                PluginFinding(
                    category="Transport Security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="Strict-Transport-Security (HSTS) header is missing.",
                    evidence="HTTPS response did not include a Strict-Transport-Security header.",
                    recommendation=(
                        "Set 'Strict-Transport-Security: max-age=31536000; "
                        "includeSubDomains' on all HTTPS responses."
                    ),
                    technical_impact=(
                        "Users may be susceptible to SSL-stripping / downgrade attacks."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-319",
                )
            ]

        return []


class HttpsEnforcementPlugin:
    metadata = PluginMetadata(
        plugin_id="https-enforcement",
        name="HTTPS Enforcement",
        version="1.0.0",
        category="Transport Security",
        description="Flags targets served over plaintext HTTP.",
        execution_priority=5,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        if context.is_https:
            return []

        return [
            PluginFinding(
                category="Transport Security",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description="The page is served over plaintext HTTP.",
                evidence=f"Target URL '{context.url}' does not use HTTPS.",
                recommendation="Serve all application traffic exclusively over HTTPS.",
                technical_impact="Traffic can be intercepted or modified in transit.",
                owasp_reference="A02:2021 - Cryptographic Failures",
                cwe_reference="CWE-319",
            )
        ]


class CookieSecurityPlugin:
    metadata = PluginMetadata(
        plugin_id="cookie-security",
        name="Cookie Security",
        version="1.0.0",
        category="Cookies",
        description="Checks cookies for Secure, HttpOnly, and SameSite attributes.",
        execution_priority=25,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        set_cookie_headers = context.response.headers.get_list("set-cookie")

        for raw_cookie in set_cookie_headers:
            name = raw_cookie.split("=", 1)[0].strip()
            lowered = raw_cookie.lower()

            missing = []
            if "secure" not in lowered and context.is_https:
                missing.append("Secure")
            if "httponly" not in lowered:
                missing.append("HttpOnly")
            if "samesite" not in lowered:
                missing.append("SameSite")

            if missing:
                findings.append(
                    PluginFinding(
                        category="Cookies",
                        severity=Severity.MEDIUM if "HttpOnly" in missing else Severity.LOW,
                        confidence=Confidence.HIGH,
                        description=f"Cookie '{name}' is missing recommended attributes.",
                        evidence=f"Set-Cookie header missing: {', '.join(missing)}.",
                        recommendation=(
                            "Set the Secure, HttpOnly, and SameSite attributes "
                            "on all session and sensitive cookies."
                        ),
                        technical_impact=(
                            "Cookies may be exposed to script access or transmitted "
                            "over insecure channels."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-1004",
                    )
                )

        return findings


class ServerDisclosurePlugin:
    metadata = PluginMetadata(
        plugin_id="server-disclosure",
        name="Server Header Disclosure",
        version="1.0.0",
        category="Information Disclosure",
        description="Flags disclosure of server or framework versions.",
        execution_priority=30,
    )

    _HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator")

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        findings: list[PluginFinding] = []
        headers = {k.lower(): v for k, v in context.response.headers.items()}

        for header in self._HEADERS:
            value = headers.get(header)
            if value:
                findings.append(
                    PluginFinding(
                        category="Information Disclosure",
                        severity=Severity.INFORMATIONAL,
                        confidence=Confidence.HIGH,
                        description=f"'{header}' header discloses backend technology details.",
                        evidence=f"{header}: {value}",
                        recommendation=(
                            f"Remove or mask the '{header}' response header in production."
                        ),
                        technical_impact="Aids attackers in fingerprinting the technology stack.",
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-200",
                    )
                )

        return findings


class CacheControlPlugin:
    metadata = PluginMetadata(
        plugin_id="cache-control",
        name="Cache Control",
        version="1.0.0",
        category="Best Practice Checks",
        description="Checks for missing cache-control directives.",
        execution_priority=60,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        headers = {k.lower(): v for k, v in context.response.headers.items()}

        if "cache-control" not in headers:
            return [
                PluginFinding(
                    category="Best Practice Checks",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    description="Cache-Control header is not set.",
                    evidence="Response did not include a Cache-Control directive.",
                    recommendation=(
                        "Set an explicit Cache-Control policy, especially "
                        "'no-store' on pages containing sensitive data."
                    ),
                    technical_impact="Sensitive content may be cached by intermediaries.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                )
            ]

        return []


class MixedContentPlugin:
    metadata = PluginMetadata(
        plugin_id="mixed-content",
        name="Mixed Content Indicators",
        version="1.0.0",
        category="Transport Security",
        description="Flags plaintext HTTP resource references on HTTPS pages.",
        execution_priority=40,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        if not context.is_https:
            return []

        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        body = context.response.text
        needle = 'src="http://'

        if needle in body or "src='http://" in body:
            return [
                PluginFinding(
                    category="Transport Security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description="Page appears to load resources over plaintext HTTP.",
                    evidence="HTML source contains one or more 'http://' resource references.",
                    recommendation="Serve all page resources (scripts, images, styles) over HTTPS.",
                    technical_impact="Mixed content weakens the page's transport security guarantees.",
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-319",
                )
            ]

        return []


class ContentSecurityPolicyAnalysisPlugin:
    """
    Parses an existing CSP header (SecurityHeadersPlugin only flags
    absence) for common weaknesses: unsafe-inline / unsafe-eval,
    wildcard sources, and missing object-src / frame-ancestors.
    """

    metadata = PluginMetadata(
        plugin_id="csp-directive-analysis",
        name="Content Security Policy Analysis",
        version="1.0.0",
        category="HTTP Headers",
        description="Parses CSP directives for unsafe-inline, wildcard sources, and missing hardening directives.",
        execution_priority=22,
    )

    _RISKY_SOURCE_DIRECTIVES = ("script-src", "style-src", "default-src")

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        headers = {k.lower(): v for k, v in context.response.headers.items()}
        csp = headers.get("content-security-policy")

        if not csp:
            return []

        directives: dict[str, str] = {}
        for part in csp.split(";"):
            part = part.strip()
            if not part:
                continue
            tokens = part.split(None, 1)
            name = tokens[0].lower()
            value = tokens[1] if len(tokens) > 1 else ""
            directives[name] = value

        findings: list[PluginFinding] = []

        for directive in self._RISKY_SOURCE_DIRECTIVES:
            value = directives.get(directive)
            if value is None:
                continue

            if "'unsafe-inline'" in value or "'unsafe-eval'" in value:
                unsafe = [
                    kw
                    for kw in ("'unsafe-inline'", "'unsafe-eval'")
                    if kw in value
                ]
                findings.append(
                    PluginFinding(
                        category="HTTP Headers",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            f"CSP directive '{directive}' permits {', '.join(unsafe)}, "
                            "substantially weakening XSS protection."
                        ),
                        evidence=f"{directive}: {value}",
                        recommendation=(
                            f"Remove {', '.join(unsafe)} from '{directive}' and use "
                            "nonces or hashes for required inline scripts/styles."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-79",
                    )
                )

            if "*" in value.split():
                findings.append(
                    PluginFinding(
                        category="HTTP Headers",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=(
                            f"CSP directive '{directive}' allows a wildcard ('*') source."
                        ),
                        evidence=f"{directive}: {value}",
                        recommendation=(
                            f"Restrict '{directive}' to an explicit allowlist of trusted origins."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                    )
                )

        if "object-src" not in directives and "default-src" not in directives:
            findings.append(
                PluginFinding(
                    category="HTTP Headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="CSP does not restrict 'object-src'.",
                    evidence=f"Content-Security-Policy: {csp}",
                    recommendation="Add \"object-src 'none'\" unless plugins/embeds are required.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                )
            )

        if "frame-ancestors" not in directives:
            findings.append(
                PluginFinding(
                    category="HTTP Headers",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description="CSP does not set 'frame-ancestors', so it does not mitigate clickjacking on its own.",
                    evidence=f"Content-Security-Policy: {csp}",
                    recommendation="Add a 'frame-ancestors' directive (e.g. 'self') alongside X-Frame-Options.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-1021",
                )
            )

        return findings


class CookieScopePlugin:
    """
    Flags cookies explicitly scoped to a parent/apex domain broader
    than the host that set them (e.g. Domain=.example.com set by
    app.example.com), which exposes the cookie to every subdomain.
    """

    metadata = PluginMetadata(
        plugin_id="cookie-scope",
        name="Cookie Domain Scope",
        version="1.0.0",
        category="Cookies",
        description="Flags cookies scoped to a parent domain broader than the responding host.",
        execution_priority=27,
    )

    _DOMAIN_ATTR = re.compile(r"domain=([^;]+)", re.IGNORECASE)

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        host = urlparse(context.url).hostname or ""
        findings: list[PluginFinding] = []

        for raw_cookie in context.response.headers.get_list("set-cookie"):
            match = self._DOMAIN_ATTR.search(raw_cookie)
            if not match:
                continue

            cookie_domain = match.group(1).strip().lstrip(".").lower()
            name = raw_cookie.split("=", 1)[0].strip()

            if not cookie_domain or cookie_domain == host:
                continue

            host_labels = host.split(".")
            cookie_labels = cookie_domain.split(".")

            # Broader than the exact host and not just a bare eTLD+1 that
            # matches the host's own registrable domain closely enough
            # to be routine (heuristic: fewer labels than host = broader).
            if host.endswith(cookie_domain) and len(cookie_labels) < len(host_labels):
                findings.append(
                    PluginFinding(
                        category="Cookies",
                        severity=Severity.LOW,
                        confidence=Confidence.MEDIUM,
                        description=f"Cookie '{name}' is scoped to the parent domain '{cookie_domain}'.",
                        evidence=f"Set-Cookie Domain attribute: {cookie_domain}",
                        recommendation=(
                            "Scope cookies to the exact host that needs them rather than "
                            "a parent domain, unless cross-subdomain sharing is required."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-16",
                    )
                )

        return findings


class PasswordAutocompletePlugin:
    metadata = PluginMetadata(
        plugin_id="password-autocomplete",
        name="Password Field Autocomplete",
        version="1.0.0",
        category="Best Practice Checks",
        description="Flags password input fields that do not disable autocomplete.",
        execution_priority=65,
    )

    _PASSWORD_INPUT = re.compile(
        r'<input\b[^>]*type=["\']password["\'][^>]*>', re.IGNORECASE
    )
    _AUTOCOMPLETE_OFF = re.compile(
        r'autocomplete=["\'](off|new-password|current-password)["\']', re.IGNORECASE
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        body = context.response.text
        fields = self._PASSWORD_INPUT.findall(body)

        exposed = [f for f in fields if not self._AUTOCOMPLETE_OFF.search(f)]

        if not exposed:
            return []

        return [
            PluginFinding(
                category="Best Practice Checks",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    f"{len(exposed)} password field(s) do not explicitly disable autocomplete."
                ),
                evidence=exposed[0][:200],
                recommendation=(
                    "Set autocomplete=\"new-password\" or \"current-password\" on "
                    "password fields to reduce credential caching in shared browsers."
                ),
                owasp_reference="A07:2021 - Identification and Authentication Failures",
                cwe_reference="CWE-200",
            )
        ]


class FileUploadDetectionPlugin:
    metadata = PluginMetadata(
        plugin_id="file-upload-detection",
        name="File Upload Functionality",
        version="1.0.0",
        category="Best Practice Checks",
        description="Notes the presence of file upload fields for manual review.",
        execution_priority=90,
    )

    _FILE_INPUT = re.compile(r'<input\b[^>]*type=["\']file["\'][^>]*>', re.IGNORECASE)

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        if not self._FILE_INPUT.search(context.response.text):
            return []

        return [
            PluginFinding(
                category="Best Practice Checks",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.HIGH,
                description="This page contains file upload functionality.",
                evidence="Detected an <input type=\"file\"> element.",
                recommendation=(
                    "Ensure uploads are validated (type, size, content), stored "
                    "outside the web root or in object storage, and served with "
                    "safe content types to prevent stored XSS or RCE via upload."
                ),
                owasp_reference="A04:2021 - Insecure Design",
                cwe_reference="CWE-434",
            )
        ]


class SensitiveDataExposurePlugin:
    """
    Passive regex scan for obviously sensitive material left in page
    responses: private key material, embedded DB connection-string
    credentials, cloud access keys, and (lower severity) bare email
    addresses.
    """

    metadata = PluginMetadata(
        plugin_id="sensitive-data-exposure",
        name="Sensitive Data Exposure",
        version="1.0.0",
        category="Information Disclosure",
        description="Scans response bodies for exposed secrets, credentials, and PII patterns.",
        execution_priority=15,
    )

    _PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
    _AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
    _DB_CONN_STRING = re.compile(
        r"(mongodb(\+srv)?|postgres(ql)?|mysql|redis)://[^:\s]+:[^@\s]+@|"
        r"(Server|Data Source)=[^;]+;.*Password=[^;]+;",
        re.IGNORECASE,
    )
    _EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if not any(t in content_type for t in ("text/", "json", "javascript", "xml")):
            return []

        body = context.response.text
        findings: list[PluginFinding] = []

        if self._PRIVATE_KEY.search(body):
            findings.append(
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="A private key appears to be exposed in the response.",
                    evidence="Response body contains a PEM private key header.",
                    recommendation="Remove the private key from public responses and rotate it immediately.",
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-200",
                )
            )

        if self._AWS_KEY.search(body):
            findings.append(
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description="A pattern matching an AWS access key ID was found in the response.",
                    evidence="Response body contains a string matching AKIA[0-9A-Z]{16}.",
                    recommendation="Rotate the credential immediately and remove it from client-facing responses.",
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-798",
                )
            )

        conn_match = self._DB_CONN_STRING.search(body)
        if conn_match:
            findings.append(
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description="A database connection string with embedded credentials appears in the response.",
                    evidence=conn_match.group(0)[:120],
                    recommendation=(
                        "Remove connection strings from client-facing responses and "
                        "load credentials from a secrets manager server-side only."
                    ),
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-798",
                )
            )

        emails = set(self._EMAIL.findall(body))
        if emails:
            findings.append(
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.LOW,
                    description=f"{len(emails)} email address(es) found in the response body.",
                    evidence=", ".join(sorted(emails)[:5]),
                    recommendation="Confirm these addresses are intended to be public.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-200",
                )
            )

        return findings


class XXssProtectionPlugin:
    metadata = PluginMetadata(
        plugin_id="x-xss-protection",
        name="X-XSS-Protection Header",
        version="1.0.0",
        category="HTTP Headers",
        description="Flags responses that explicitly disable the legacy browser XSS filter.",
        execution_priority=70,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        value = context.response.headers.get("x-xss-protection")

        if value and value.strip().startswith("0"):
            return [
                PluginFinding(
                    category="HTTP Headers",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.HIGH,
                    description="The X-XSS-Protection header explicitly disables the browser's legacy XSS filter.",
                    evidence=f"X-XSS-Protection: {value}",
                    recommendation=(
                        "This header is deprecated in modern browsers in favor of CSP; "
                        "either remove it or rely on a strong Content-Security-Policy instead."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                )
            ]

        return []


class VulnerableJsLibraryPlugin:
    """
    Curated, deliberately small table of well-known vulnerable
    front-end library versions. This is fingerprinting via
    <script src> version strings, not a live CVE feed.
    """

    metadata = PluginMetadata(
        plugin_id="vulnerable-js-library",
        name="Vulnerable JavaScript Dependency",
        version="1.0.0",
        category="Best Practice Checks",
        description="Flags known-vulnerable versions of common front-end libraries referenced via <script src>.",
        execution_priority=50,
    )

    # (library display name, filename match pattern, version regex, max safe version tuple, advisory)
    _LIBRARIES = (
        ("jQuery", re.compile(r"jquery[.-](\d+\.\d+\.\d+)", re.I), (3, 5, 0), "CVE-2020-11022/11023 (XSS via untrusted HTML)"),
        ("Bootstrap", re.compile(r"bootstrap[.-](\d+\.\d+\.\d+)", re.I), (3, 4, 1), "XSS in data-target/tooltip/popover"),
        ("Angular.js", re.compile(r"angular(?:\.min)?[.-]?(\d+\.\d+\.\d+)\.js", re.I), (1, 6, 0), "Sandbox bypass leading to XSS"),
        ("Lodash", re.compile(r"lodash[.-](\d+\.\d+\.\d+)", re.I), (4, 17, 12), "CVE-2019-10744 (prototype pollution)"),
        ("Moment.js", re.compile(r"moment[.-](\d+\.\d+\.\d+)", re.I), (2, 29, 4), "CVE-2022-31129 (ReDoS)"),
    )

    _SCRIPT_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.IGNORECASE)

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        sources = self._SCRIPT_SRC.findall(context.response.text)
        findings: list[PluginFinding] = []

        for src in sources:
            for lib_name, pattern, max_safe, advisory in self._LIBRARIES:
                match = pattern.search(src)
                if not match:
                    continue

                try:
                    version = tuple(int(p) for p in match.group(1).split("."))
                except ValueError:
                    continue

                if version < max_safe:
                    findings.append(
                        PluginFinding(
                            category="Best Practice Checks",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.MEDIUM,
                            description=(
                                f"{lib_name} {'.'.join(map(str, version))} is an outdated "
                                "version with known vulnerabilities."
                            ),
                            evidence=f"Script source: {src}",
                            recommendation=(
                                f"Upgrade {lib_name} to {'.'.join(map(str, max_safe))} or later. "
                                f"Relevant advisory: {advisory}"
                            ),
                            owasp_reference="A06:2021 - Vulnerable and Outdated Components",
                            cwe_reference="CWE-1104",
                        )
                    )

        return findings


class SubresourceIntegrityPlugin:
    metadata = PluginMetadata(
        plugin_id="subresource-integrity",
        name="Subresource Integrity",
        version="1.0.0",
        category="Best Practice Checks",
        description="Flags cross-origin scripts/stylesheets loaded without a Subresource Integrity hash.",
        execution_priority=80,
    )

    _SCRIPT_OR_LINK = re.compile(
        r'<(script|link)\b([^>]*)>', re.IGNORECASE
    )
    _SRC_OR_HREF = re.compile(r'(?:src|href)=["\'](https?://[^"\']+)["\']', re.IGNORECASE)
    _REL_STYLESHEET = re.compile(r'rel=["\']stylesheet["\']', re.IGNORECASE)

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        page_host = urlparse(context.url).hostname
        body = context.response.text
        missing: list[str] = []

        for tag, attrs in self._SCRIPT_OR_LINK.findall(body):
            if "integrity=" in attrs.lower():
                continue

            if tag.lower() == "link" and not self._REL_STYLESHEET.search(attrs):
                continue

            src_match = self._SRC_OR_HREF.search(attrs)
            if not src_match:
                continue

            resource_host = urlparse(src_match.group(1)).hostname
            if resource_host and resource_host != page_host:
                missing.append(src_match.group(1))

        if not missing:
            return []

        return [
            PluginFinding(
                category="Best Practice Checks",
                severity=Severity.LOW,
                confidence=Confidence.MEDIUM,
                description=(
                    f"{len(missing)} cross-origin script/stylesheet reference(s) "
                    "are loaded without a Subresource Integrity (integrity=) attribute."
                ),
                evidence=missing[0],
                recommendation=(
                    "Add integrity and crossorigin attributes to third-party "
                    "<script>/<link> tags so a compromised CDN can't silently "
                    "serve modified content."
                ),
                owasp_reference="A08:2021 - Software and Data Integrity Failures",
                cwe_reference="CWE-353",
            )
        ]


class CookiePrefixPlugin:
    metadata = PluginMetadata(
        plugin_id="cookie-prefix-hygiene",
        name="Cookie Prefix Hygiene",
        version="1.0.0",
        category="Cookies",
        description="Flags __Secure-/__Host- prefixed cookies that don't satisfy the prefix's requirements.",
        execution_priority=26,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        findings: list[PluginFinding] = []

        for raw_cookie in context.response.headers.get_list("set-cookie"):
            name = raw_cookie.split("=", 1)[0].strip()
            lowered = raw_cookie.lower()

            if name.startswith("__Host-"):
                problems = []
                if "secure" not in lowered:
                    problems.append("missing Secure")
                if "domain=" in lowered:
                    problems.append("sets a Domain attribute (not allowed)")
                if "path=/" not in lowered.replace(" ", ""):
                    problems.append("does not scope Path=/")

                if problems:
                    findings.append(self._finding(name, "__Host-", problems))

            elif name.startswith("__Secure-"):
                if "secure" not in lowered:
                    findings.append(self._finding(name, "__Secure-", ["missing Secure"]))

        return findings

    @staticmethod
    def _finding(name: str, prefix: str, problems: list[str]) -> PluginFinding:
        return PluginFinding(
            category="Cookies",
            severity=Severity.LOW,
            confidence=Confidence.HIGH,
            description=f"Cookie '{name}' uses the {prefix} prefix but violates its requirements.",
            evidence=", ".join(problems),
            recommendation=(
                f"Either satisfy the {prefix} prefix requirements or rename the "
                "cookie to not claim guarantees it doesn't provide."
            ),
            owasp_reference="A05:2021 - Security Misconfiguration",
            cwe_reference="CWE-16",
        )


class InsecureFormActionPlugin:
    metadata = PluginMetadata(
        plugin_id="insecure-form-action",
        name="Insecure Form Action",
        version="1.0.0",
        category="Transport Security",
        description="Flags forms on an HTTPS page that submit to a plaintext HTTP action.",
        execution_priority=24,
    )

    _FORM_ACTION = re.compile(r'<form\b[^>]*action=["\'](http://[^"\']+)["\']', re.IGNORECASE)

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        if not context.is_https:
            return []

        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        match = self._FORM_ACTION.search(context.response.text)
        if not match:
            return []

        return [
            PluginFinding(
                category="Transport Security",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description="A form on this HTTPS page submits to a plaintext HTTP action.",
                evidence=f"<form action=\"{match.group(1)}\" ...>",
                recommendation="Change the form action to HTTPS so submitted data isn't sent in cleartext.",
                owasp_reference="A02:2021 - Cryptographic Failures",
                cwe_reference="CWE-319",
            )
        ]


class CsrfTokenPresencePlugin:
    """
    Structural check only: does each POST form carry a hidden field
    that looks like an anti-CSRF token? This cannot confirm the token
    is actually validated server-side, only that one is present.
    """

    metadata = PluginMetadata(
        plugin_id="csrf-token-presence",
        name="CSRF Token Presence",
        version="1.0.0",
        category="Authorization Indicators",
        description="Flags state-changing forms with no apparent anti-CSRF token field.",
        execution_priority=45,
    )

    _FORM_BLOCK = re.compile(r"<form\b([^>]*)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    _METHOD_POST = re.compile(r'method=["\']post["\']', re.IGNORECASE)
    _HIDDEN_TOKEN_FIELD = re.compile(
        r'<input\b[^>]*type=["\']hidden["\'][^>]*name=["\'][^"\']*'
        r"(csrf|token|authenticity|nonce|_token)[^\"']*[\"']",
        re.IGNORECASE,
    )

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        content_type = context.response.headers.get("content-type", "")
        if "text/html" not in content_type:
            return []

        forms_without_token = 0

        for attrs, body in self._FORM_BLOCK.findall(context.response.text):
            if not self._METHOD_POST.search(attrs):
                continue

            if not self._HIDDEN_TOKEN_FIELD.search(body):
                forms_without_token += 1

        if forms_without_token == 0:
            return []

        return [
            PluginFinding(
                category="Authorization Indicators",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                description=(
                    f"{forms_without_token} POST form(s) on this page have no "
                    "apparent hidden anti-CSRF token field."
                ),
                evidence="No hidden input matching csrf/token/authenticity/nonce found in form body.",
                recommendation=(
                    "Confirm CSRF protection is applied server-side (e.g. via a "
                    "framework-level CSRF middleware using headers/cookies rather "
                    "than a hidden field, in which case this is a false positive)."
                ),
                owasp_reference="A01:2021 - Broken Access Control",
                cwe_reference="CWE-352",
            )
        ]


class PassiveJwtInspectionPlugin:
    """
    Looks for JWT-shaped tokens in cookies and response bodies and
    inspects the (unsigned, base64-decoded) header only - no signature
    verification or cracking is attempted. Flags the well-known
    passively-detectable red flags: alg=none, and arbitrary jku/x5u
    headers that let an attacker point signature verification at a
    key they control.
    """

    metadata = PluginMetadata(
        plugin_id="passive-jwt-inspection",
        name="Passive JWT Inspection",
        version="1.0.0",
        category="Authentication Indicators",
        description="Decodes JWT headers found in traffic to flag alg=none and arbitrary jku/x5u.",
        execution_priority=35,
    )

    _JWT_PATTERN = re.compile(r"\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*\b")

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        import base64
        import json

        candidates: set[str] = set()

        for raw_cookie in context.response.headers.get_list("set-cookie"):
            candidates.update(self._JWT_PATTERN.findall(raw_cookie))

        content_type = context.response.headers.get("content-type", "")
        if any(t in content_type for t in ("text/", "json", "javascript")):
            candidates.update(self._JWT_PATTERN.findall(context.response.text))

        findings: list[PluginFinding] = []

        for token in candidates:
            header_b64 = token.split(".")[0]
            padded = header_b64 + "=" * (-len(header_b64) % 4)

            try:
                header = json.loads(base64.urlsafe_b64decode(padded))
            except Exception:  # noqa: BLE001 - malformed/non-JWT lookalike
                continue

            alg = str(header.get("alg", "")).lower()

            if alg == "none":
                findings.append(
                    PluginFinding(
                        category="Authentication Indicators",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        description="A JWT observed in traffic declares alg=none.",
                        evidence=f"Decoded JWT header: {header}",
                        recommendation=(
                            "Reject tokens with alg=none server-side; explicitly "
                            "allowlist expected signing algorithms."
                        ),
                        owasp_reference="A02:2021 - Cryptographic Failures",
                        cwe_reference="CWE-347",
                    )
                )

            if "jku" in header or "x5u" in header:
                findings.append(
                    PluginFinding(
                        category="Authentication Indicators",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        description="A JWT observed in traffic carries a jku/x5u header pointing to an external key URL.",
                        evidence=f"Decoded JWT header: {header}",
                        recommendation=(
                            "If jku/x5u are used, strictly allowlist trusted key "
                            "hosts server-side rather than trusting the header value."
                        ),
                        owasp_reference="A02:2021 - Cryptographic Failures",
                        cwe_reference="CWE-347",
                    )
                )

        return findings


PAGE_PLUGINS: list = [
    HttpsEnforcementPlugin(),
    HstsPlugin(),
    SecurityHeadersPlugin(),
    ContentSecurityPolicyAnalysisPlugin(),
    CookieSecurityPlugin(),
    CookieScopePlugin(),
    CookiePrefixPlugin(),
    ServerDisclosurePlugin(),
    CacheControlPlugin(),
    MixedContentPlugin(),
    InsecureFormActionPlugin(),
    PasswordAutocompletePlugin(),
    FileUploadDetectionPlugin(),
    CsrfTokenPresencePlugin(),
    SensitiveDataExposurePlugin(),
    PassiveJwtInspectionPlugin(),
    XXssProtectionPlugin(),
    VulnerableJsLibraryPlugin(),
    SubresourceIntegrityPlugin(),
]
