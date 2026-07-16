"""
Site-level (non-per-page) vulnerability checks.

These run once per scan against the target's root, mirroring the
built-in plugins listed in FRS Part 3, Section 65 that operate at
the site level rather than the page level (robots.txt, security.txt,
.git exposure, HTTP methods, TLS configuration, technology
fingerprinting, directory listing, backup file exposure).
"""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import UTC, datetime, timedelta
from urllib.parse import urlparse

import httpx

from app.domains.finding.domain.enums import Confidence, Severity
from app.domains.scan.services.plugin_base import PluginFinding

_SITE_TIMEOUT = 8.0


async def run_site_checks(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    """
    Returns a list of (plugin_id, plugin_name, finding) tuples.
    """

    results: list[tuple[str, str, PluginFinding]] = []

    results.extend(await _check_robots_txt(client, base_url))
    results.extend(await _check_security_txt(client, base_url))
    results.extend(await _check_git_exposure(client, base_url))
    results.extend(await _check_http_methods(client, base_url))
    results.extend(await _check_tls_configuration(base_url))
    results.extend(await _check_technology_fingerprint(client, base_url))
    results.extend(await _check_directory_listing(client, base_url))
    results.extend(await _check_backup_file_exposure(client, base_url))
    results.extend(await _check_cors_misconfiguration(client, base_url))
    results.extend(await _check_api_discovery(client, base_url))
    results.extend(await _check_aspnet_diagnostics(client, base_url))
    results.extend(await _check_sitemap(client, base_url))
    results.extend(await _check_favicon_fingerprint(client, base_url))

    return results


async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(url, timeout=_SITE_TIMEOUT, follow_redirects=True)
    except httpx.HTTPError:
        return None


async def _check_robots_txt(client, base_url):
    response = await _safe_get(client, f"{base_url.rstrip('/')}/robots.txt")

    if response is None or response.status_code != 200:
        return [
            (
                "robots-txt",
                "robots.txt",
                PluginFinding(
                    category="Best Practice Checks",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    description="robots.txt was not found.",
                    evidence=f"Request to /robots.txt returned "
                    f"{response.status_code if response else 'no response'}.",
                    recommendation=(
                        "Publish a robots.txt to control crawler access, "
                        "or confirm this omission is intentional."
                    ),
                ),
            )
        ]

    sensitive_hints = ("admin", "wp-admin", "config", "backup", ".env")
    disclosed = [
        line.strip()
        for line in response.text.splitlines()
        if any(hint in line.lower() for hint in sensitive_hints)
    ]

    if disclosed:
        return [
            (
                "robots-txt",
                "robots.txt",
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    description="robots.txt discloses potentially sensitive paths.",
                    evidence="; ".join(disclosed[:5]),
                    recommendation=(
                        "Avoid listing administrative or sensitive paths in "
                        "robots.txt; rely on server-side access control instead."
                    ),
                    owasp_reference="A01:2021 - Broken Access Control",
                ),
            )
        ]

    return []


async def _check_security_txt(client, base_url):
    response = await _safe_get(
        client, f"{base_url.rstrip('/')}/.well-known/security.txt"
    )

    if response is not None and response.status_code == 200:
        return []

    return [
        (
            "security-txt",
            "security.txt",
            PluginFinding(
                category="Best Practice Checks",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                description="security.txt was not found.",
                evidence="No 200 response for /.well-known/security.txt.",
                recommendation=(
                    "Publish a security.txt file per RFC 9116 so researchers "
                    "know how to report vulnerabilities responsibly."
                ),
            ),
        )
    ]


async def _check_git_exposure(client, base_url):
    response = await _safe_get(client, f"{base_url.rstrip('/')}/.git/HEAD")

    if response is not None and response.status_code == 200 and "ref:" in response.text:
        return [
            (
                "git-exposure",
                ".git Exposure",
                PluginFinding(
                    category="Directory Exposure",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.HIGH,
                    description="The .git directory is publicly accessible.",
                    evidence="GET /.git/HEAD returned a valid git ref.",
                    recommendation=(
                        "Block access to the .git directory at the web server "
                        "or reverse proxy level immediately."
                    ),
                    technical_impact=(
                        "Full source code, history, and secrets may be reconstructable."
                    ),
                    owasp_reference="A01:2021 - Broken Access Control",
                    cwe_reference="CWE-538",
                ),
            )
        ]

    return []


async def _check_http_methods(client, base_url):
    try:
        response = await client.request(
            "OPTIONS", base_url, timeout=_SITE_TIMEOUT, follow_redirects=True
        )
    except httpx.HTTPError:
        return []

    allow = response.headers.get("allow", "")
    risky = {"PUT", "DELETE", "TRACE", "CONNECT"}
    enabled_risky = [m for m in risky if m in allow.upper()]

    if enabled_risky:
        return [
            (
                "http-methods",
                "HTTP Methods",
                PluginFinding(
                    category="Configuration Issues",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description="Potentially risky HTTP methods are enabled.",
                    evidence=f"Allow header: {allow}",
                    recommendation=(
                        "Disable HTTP methods that are not required by the "
                        "application (e.g. PUT, DELETE, TRACE)."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                ),
            )
        ]

    return []


# ----------------------------------------------------------------------
# TLS Configuration
# ----------------------------------------------------------------------

_WEAK_CIPHER_MARKERS = ("RC4", "DES", "3DES", "NULL", "EXPORT", "MD5", "ANON")
_WEAK_PROTOCOLS = ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1")
_CERT_EXPIRY_WARNING_DAYS = 30


def _tls_probe_sync(hostname: str, port: int) -> dict:
    """
    Blocking TLS handshake + certificate inspection. Run via
    asyncio.to_thread so it doesn't stall the event loop.
    """

    info: dict = {"verified": True, "error": None}

    def _connect(context: ssl.SSLContext) -> None:
        with socket.create_connection((hostname, port), timeout=_SITE_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                info["version"] = ssock.version()
                info["cipher"] = ssock.cipher()
                info["cert"] = ssock.getpeercert()

    try:
        _connect(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        info["verified"] = False
        info["error"] = str(exc)
        try:
            _connect(ssl._create_unverified_context())
        except Exception:  # noqa: BLE001 - best-effort fallback probe
            pass
    except Exception as exc:  # noqa: BLE001 - connection/handshake failure
        info["error"] = str(exc)

    return info


async def _check_tls_configuration(base_url: str) -> list[tuple[str, str, PluginFinding]]:
    parsed = urlparse(base_url)

    if parsed.scheme != "https":
        return []

    hostname = parsed.hostname
    port = parsed.port or 443

    if hostname is None:
        return []

    info = await asyncio.to_thread(_tls_probe_sync, hostname, port)
    findings: list[tuple[str, str, PluginFinding]] = []

    if info.get("error") and "cert" not in info:
        return [
            (
                "tls-configuration",
                "TLS Configuration",
                PluginFinding(
                    category="Transport Security",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description="TLS handshake with the target could not be completed.",
                    evidence=str(info["error"])[:300],
                    recommendation=(
                        "Verify the server's TLS configuration is reachable and "
                        "correctly configured for standard clients."
                    ),
                    owasp_reference="A02:2021 - Cryptographic Failures",
                ),
            )
        ]

    if not info.get("verified", True):
        findings.append(
            (
                "tls-configuration",
                "TLS Configuration",
                PluginFinding(
                    category="Transport Security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="The TLS certificate failed standard validation.",
                    evidence=str(info.get("error"))[:300],
                    recommendation=(
                        "Install a certificate issued by a trusted CA covering "
                        "this hostname, and ensure the full chain is served."
                    ),
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-295",
                ),
            )
        )

    version = info.get("version")
    if version and any(weak in version for weak in _WEAK_PROTOCOLS):
        findings.append(
            (
                "tls-configuration",
                "TLS Configuration",
                PluginFinding(
                    category="Transport Security",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"The server negotiated an outdated TLS protocol ({version}).",
                    evidence=f"Negotiated protocol: {version}",
                    recommendation="Disable SSLv2/SSLv3/TLSv1.0/TLSv1.1; require TLS 1.2 or higher.",
                    owasp_reference="A02:2021 - Cryptographic Failures",
                    cwe_reference="CWE-326",
                ),
            )
        )

    cipher = info.get("cipher")
    if cipher:
        cipher_name = cipher[0]
        if any(marker in cipher_name.upper() for marker in _WEAK_CIPHER_MARKERS):
            findings.append(
                (
                    "tls-configuration",
                    "TLS Configuration",
                    PluginFinding(
                        category="Transport Security",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"The server negotiated a weak cipher suite ({cipher_name}).",
                        evidence=f"Negotiated cipher: {cipher_name}",
                        recommendation="Disable weak/legacy cipher suites (RC4, DES/3DES, NULL, EXPORT, anonymous).",
                        owasp_reference="A02:2021 - Cryptographic Failures",
                        cwe_reference="CWE-327",
                    ),
                )
            )

    cert = info.get("cert") or {}
    not_after = cert.get("notAfter")
    if not_after:
        try:
            expires_at = datetime.strptime(
                not_after, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=UTC)
            remaining = expires_at - datetime.now(UTC)

            if remaining.total_seconds() < 0:
                findings.append(
                    (
                        "tls-configuration",
                        "TLS Configuration",
                        PluginFinding(
                            category="Transport Security",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            description="The TLS certificate has expired.",
                            evidence=f"Certificate notAfter: {not_after}",
                            recommendation="Renew the TLS certificate immediately.",
                            owasp_reference="A02:2021 - Cryptographic Failures",
                            cwe_reference="CWE-295",
                        ),
                    )
                )
            elif remaining < timedelta(days=_CERT_EXPIRY_WARNING_DAYS):
                findings.append(
                    (
                        "tls-configuration",
                        "TLS Configuration",
                        PluginFinding(
                            category="Transport Security",
                            severity=Severity.MEDIUM,
                            confidence=Confidence.HIGH,
                            description=(
                                f"The TLS certificate expires in {remaining.days} day(s)."
                            ),
                            evidence=f"Certificate notAfter: {not_after}",
                            recommendation="Renew the TLS certificate before it expires.",
                            owasp_reference="A02:2021 - Cryptographic Failures",
                        ),
                    )
                )
        except ValueError:
            pass

    return findings


# ----------------------------------------------------------------------
# Technology Fingerprinting
# ----------------------------------------------------------------------

_COOKIE_TECH_MAP = {
    "phpsessid": "PHP",
    "jsessionid": "Java (Servlet/JSP)",
    "asp.net_sessionid": "ASP.NET",
    ".aspnetcore.session": "ASP.NET Core",
    "laravel_session": "Laravel (PHP)",
    "csrftoken": "Django (Python)",
    "django_language": "Django (Python)",
    "connect.sid": "Express (Node.js)",
    "wordpress_logged_in": "WordPress",
    "wp-settings": "WordPress",
    "ci_session": "CodeIgniter (PHP)",
}

_HEADER_TECH_MAP = {
    "x-powered-by": None,  # value itself is the technology name
    "x-generator": None,
    "x-drupal-cache": "Drupal",
    "x-varnish": "Varnish",
}

_BODY_PATTERNS = (
    (re.compile(r"wp-content|wp-includes|wp-json", re.I), "WordPress"),
    (re.compile(r"/sites/default/files|Drupal\.settings", re.I), "Drupal"),
    (re.compile(r"/_next/static|__NEXT_DATA__", re.I), "Next.js"),
    (re.compile(r"ng-version=|angular", re.I), "Angular"),
    (re.compile(r"data-reactroot|react-dom", re.I), "React"),
    (re.compile(r"Shopify\.theme|cdn\.shopify\.com", re.I), "Shopify"),
    (re.compile(r"/typo3temp/|typo3conf", re.I), "TYPO3"),
)

_GENERATOR_META = re.compile(
    r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I
)


async def _check_technology_fingerprint(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    response = await _safe_get(client, base_url)

    if response is None:
        return []

    detected: set[str] = set()

    headers = {k.lower(): v for k, v in response.headers.items()}

    for header, fixed_name in _HEADER_TECH_MAP.items():
        value = headers.get(header)
        if value:
            detected.add(fixed_name or value.strip())

    for raw_cookie in response.headers.get_list("set-cookie"):
        cookie_name = raw_cookie.split("=", 1)[0].strip().lower()
        if cookie_name in _COOKIE_TECH_MAP:
            detected.add(_COOKIE_TECH_MAP[cookie_name])

    content_type = headers.get("content-type", "")
    if "text/html" in content_type:
        body = response.text

        generator_match = _GENERATOR_META.search(body)
        if generator_match:
            detected.add(generator_match.group(1).strip())

        for pattern, tech in _BODY_PATTERNS:
            if pattern.search(body):
                detected.add(tech)

    if not detected:
        return []

    return [
        (
            "technology-fingerprinting",
            "Technology Fingerprinting",
            PluginFinding(
                category="Information Disclosure",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                description="The following technologies were identified via passive fingerprinting.",
                evidence=", ".join(sorted(detected)),
                recommendation=(
                    "No action required unless disclosed versions are outdated; "
                    "consider removing version-revealing headers/meta tags in production."
                ),
                owasp_reference="A05:2021 - Security Misconfiguration",
                cwe_reference="CWE-200",
            ),
        )
    ]


# ----------------------------------------------------------------------
# Directory Listing
# ----------------------------------------------------------------------

_DIRECTORY_LISTING_PATTERN = re.compile(
    r"<title>Index of /|Directory listing for /|Parent Directory</a>", re.I
)

_COMMON_DIRECTORIES = (
    "images/",
    "uploads/",
    "assets/",
    "backup/",
    "files/",
    "static/",
    "media/",
    "tmp/",
)


async def _check_directory_listing(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    root = base_url.rstrip("/")

    responses = await asyncio.gather(
        *[_safe_get(client, f"{root}/{path}") for path in _COMMON_DIRECTORIES]
    )

    findings: list[tuple[str, str, PluginFinding]] = []

    for path, response in zip(_COMMON_DIRECTORIES, responses):
        if response is None or response.status_code != 200:
            continue

        content_type = response.headers.get("content-type", "")
        if "text/html" not in content_type:
            continue

        if _DIRECTORY_LISTING_PATTERN.search(response.text):
            findings.append(
                (
                    "directory-listing",
                    "Directory Listing",
                    PluginFinding(
                        category="Directory Exposure",
                        severity=Severity.MEDIUM,
                        confidence=Confidence.HIGH,
                        description=f"Directory listing is enabled at /{path}.",
                        evidence=f"GET /{path} returned an auto-generated directory index.",
                        recommendation=(
                            "Disable directory listing/autoindex on the web server "
                            "for this and similar directories."
                        ),
                        owasp_reference="A05:2021 - Security Misconfiguration",
                        cwe_reference="CWE-548",
                    ),
                )
            )

    return findings


# ----------------------------------------------------------------------
# Backup File Exposure
# ----------------------------------------------------------------------

_BACKUP_FILENAMES = (
    "backup.zip",
    "backup.tar.gz",
    "backup.sql",
    "site.zip",
    "site_backup.zip",
    "www.zip",
    "db.sql",
    "database.sql",
    "dump.sql",
    ".env.bak",
    ".env.save",
    "config.php.bak",
    "config.php.old",
    "config.old",
    "index.php.bak",
    "web.config.bak",
)

_BACKUP_CONTENT_TYPES = (
    "application/zip",
    "application/x-gzip",
    "application/gzip",
    "application/x-tar",
    "application/octet-stream",
    "application/sql",
    "text/x-sql",
)


async def _check_backup_file_exposure(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    root = base_url.rstrip("/")

    responses = await asyncio.gather(
        *[_safe_get(client, f"{root}/{name}") for name in _BACKUP_FILENAMES]
    )

    findings: list[tuple[str, str, PluginFinding]] = []

    for filename, response in zip(_BACKUP_FILENAMES, responses):
        if response is None or response.status_code != 200:
            continue

        content_type = response.headers.get("content-type", "").lower()
        looks_like_backup = any(ct in content_type for ct in _BACKUP_CONTENT_TYPES)

        # A same-content-type HTML "200" is very likely a custom error page
        # rather than a real backup file; only flag non-HTML 200 responses,
        # or HTML responses that are unusually small (i.e. not a full page).
        if not looks_like_backup and "text/html" in content_type and len(response.content) > 2000:
            continue

        findings.append(
            (
                "backup-file-exposure",
                "Backup File Exposure",
                PluginFinding(
                    category="Directory Exposure",
                    severity=Severity.HIGH,
                    confidence=Confidence.MEDIUM,
                    description=f"A potential backup file is publicly accessible at /{filename}.",
                    evidence=(
                        f"GET /{filename} returned HTTP 200 "
                        f"(content-type: {content_type or 'unknown'}, "
                        f"{len(response.content)} bytes)."
                    ),
                    recommendation=(
                        "Remove backup files from the web root or block access to "
                        "them at the server/reverse-proxy level."
                    ),
                    owasp_reference="A01:2021 - Broken Access Control",
                    cwe_reference="CWE-530",
                ),
            )
        )

    return findings


# ----------------------------------------------------------------------
# CORS Misconfiguration (reflected-origin test)
# ----------------------------------------------------------------------

_TEST_ORIGIN = "https://ssai-cors-probe.invalid"


async def _check_cors_misconfiguration(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    try:
        response = await client.get(
            base_url,
            headers={"Origin": _TEST_ORIGIN},
            timeout=_SITE_TIMEOUT,
            follow_redirects=True,
        )
    except httpx.HTTPError:
        return []

    acao = response.headers.get("access-control-allow-origin")
    acac = response.headers.get("access-control-allow-credentials", "").lower()

    if acao is None:
        return []

    findings: list[tuple[str, str, PluginFinding]] = []

    if acao == _TEST_ORIGIN:
        severity = Severity.HIGH if acac == "true" else Severity.MEDIUM
        findings.append(
            (
                "cors-misconfiguration",
                "Cross-Origin Resource Sharing",
                PluginFinding(
                    category="Configuration Issues",
                    severity=severity,
                    confidence=Confidence.HIGH,
                    description=(
                        "The server reflects an arbitrary Origin header back in "
                        "Access-Control-Allow-Origin"
                        + (
                            " with Access-Control-Allow-Credentials: true, allowing "
                            "any site to make authenticated cross-origin requests."
                            if acac == "true"
                            else "."
                        )
                    ),
                    evidence=(
                        f"Sent Origin: {_TEST_ORIGIN} -> "
                        f"Access-Control-Allow-Origin: {acao}, "
                        f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                    ),
                    recommendation=(
                        "Validate the Origin header against an explicit allowlist "
                        "server-side instead of reflecting it; never combine a "
                        "reflected/wildcard origin with allow-credentials: true."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-942",
                ),
            )
        )
    elif acao == "*" and acac == "true":
        # Technically invalid per the Fetch spec (browsers reject this
        # combination), but worth flagging as a server-side misconfiguration.
        findings.append(
            (
                "cors-misconfiguration",
                "Cross-Origin Resource Sharing",
                PluginFinding(
                    category="Configuration Issues",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=(
                        "The server sends Access-Control-Allow-Origin: * together with "
                        "Access-Control-Allow-Credentials: true, an invalid combination "
                        "browsers reject but which signals a misconfigured CORS policy."
                    ),
                    evidence="Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: true",
                    recommendation="Do not send allow-credentials: true alongside a wildcard origin.",
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-942",
                ),
            )
        )

    return findings


# ----------------------------------------------------------------------
# OpenAPI / Swagger / GraphQL Endpoint Discovery
# ----------------------------------------------------------------------

_API_DISCOVERY_PATHS = (
    ("openapi.json", "OpenAPI definition"),
    ("swagger.json", "Swagger definition"),
    ("swagger/v1/swagger.json", "Swagger definition"),
    ("v2/api-docs", "Swagger/OpenAPI definition"),
    ("api-docs", "API documentation"),
    ("swagger-ui/", "Swagger UI"),
    ("swagger-ui.html", "Swagger UI"),
    ("graphql", "GraphQL endpoint"),
    ("graphiql", "GraphiQL interface"),
)

_GRAPHQL_INTROSPECTION_QUERY = {
    "query": "query { __schema { types { name } } }"
}


async def _check_api_discovery(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    root = base_url.rstrip("/")

    responses = await asyncio.gather(
        *[_safe_get(client, f"{root}/{path}") for path, _ in _API_DISCOVERY_PATHS]
    )

    findings: list[tuple[str, str, PluginFinding]] = []
    graphql_url: str | None = None

    for (path, label), response in zip(_API_DISCOVERY_PATHS, responses):
        if response is None or response.status_code != 200:
            continue

        content_type = response.headers.get("content-type", "")
        if len(response.content) < 20:
            continue

        findings.append(
            (
                "api-discovery",
                "API Discovery",
                PluginFinding(
                    category="Information Disclosure",
                    severity=Severity.INFORMATIONAL,
                    confidence=Confidence.MEDIUM,
                    description=f"{label} found at /{path}.",
                    evidence=f"GET /{path} returned HTTP 200 (content-type: {content_type or 'unknown'}).",
                    recommendation=(
                        "Confirm this API documentation/endpoint is intended to be "
                        "publicly accessible and does not expose internal-only routes."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                ),
            )
        )

        if "graphql" in path and "graphiql" not in path:
            graphql_url = f"{root}/{path}"

    if graphql_url:
        findings.extend(await _check_graphql_introspection(client, graphql_url))

    return findings


async def _check_graphql_introspection(
    client: httpx.AsyncClient, graphql_url: str
) -> list[tuple[str, str, PluginFinding]]:
    try:
        response = await client.post(
            graphql_url,
            json=_GRAPHQL_INTROSPECTION_QUERY,
            timeout=_SITE_TIMEOUT,
        )
    except httpx.HTTPError:
        return []

    if response.status_code != 200:
        return []

    try:
        body = response.json()
    except ValueError:
        return []

    types = body.get("data", {}).get("__schema", {}).get("types")

    if not types:
        return []

    return [
        (
            "graphql-introspection",
            "GraphQL Introspection Enabled",
            PluginFinding(
                category="Information Disclosure",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                description="GraphQL introspection is enabled, exposing the full schema.",
                evidence=f"Introspection query against {graphql_url} returned {len(types)} type(s).",
                recommendation=(
                    "Disable introspection in production, or restrict it to "
                    "authenticated internal clients."
                ),
                owasp_reference="A05:2021 - Security Misconfiguration",
                cwe_reference="CWE-200",
            ),
        )
    ]


# ----------------------------------------------------------------------
# ASP.NET Tracing / Debugging
# ----------------------------------------------------------------------

async def _check_aspnet_diagnostics(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    root = base_url.rstrip("/")
    findings: list[tuple[str, str, PluginFinding]] = []

    trace_response = await _safe_get(client, f"{root}/trace.axd")
    if (
        trace_response is not None
        and trace_response.status_code == 200
        and ("Request Details" in trace_response.text or "Trace Information" in trace_response.text)
    ):
        findings.append(
            (
                "aspnet-tracing",
                "ASP.NET Tracing Enabled",
                PluginFinding(
                    category="Configuration Issues",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description="ASP.NET application tracing (trace.axd) is publicly accessible.",
                    evidence="GET /trace.axd returned a live trace viewer.",
                    recommendation=(
                        "Disable tracing in production (<trace enabled=\"false\"/> in web.config) "
                        "or restrict trace.axd to localhost."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-11",
                ),
            )
        )

    probe_response = await _safe_get(
        client, f"{root}/ssai-debug-probe-{socket.gethostname()[:8]}-nonexistent"
    )
    if probe_response is not None and (
        "Server Error in '/' Application" in probe_response.text
        and "Stack Trace:" in probe_response.text
    ):
        findings.append(
            (
                "aspnet-debugging",
                "ASP.NET Debugging Enabled",
                PluginFinding(
                    category="Configuration Issues",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description="ASP.NET custom errors are disabled, exposing stack traces to end users.",
                    evidence="An invalid path returned a full ASP.NET debug error page with a stack trace.",
                    recommendation=(
                        "Set <customErrors mode=\"On\"/> (or RemoteOnly) and "
                        "<compilation debug=\"false\"/> in web.config for production."
                    ),
                    owasp_reference="A05:2021 - Security Misconfiguration",
                    cwe_reference="CWE-11",
                ),
            )
        )

    return findings


# ----------------------------------------------------------------------
# Sitemap Discovery
# ----------------------------------------------------------------------

async def _check_sitemap(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    response = await _safe_get(client, f"{base_url.rstrip('/')}/sitemap.xml")

    if response is None or response.status_code != 200:
        return []

    content_type = response.headers.get("content-type", "")
    if "xml" not in content_type and "<urlset" not in response.text[:500]:
        return []

    url_count = response.text.count("<loc>")

    return [
        (
            "sitemap-discovery",
            "Sitemap Discovery",
            PluginFinding(
                category="Information Disclosure",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.MEDIUM,
                description="A sitemap.xml was found, which may reveal URLs not otherwise linked from crawled pages.",
                evidence=f"GET /sitemap.xml returned {url_count or 'an unknown number of'} <loc> entries.",
                recommendation=(
                    "Confirm every listed URL is intended to be publicly "
                    "discoverable; do not list internal/admin paths."
                ),
                references=["https://www.sitemaps.org/protocol.html"],
            ),
        )
    ]


# ----------------------------------------------------------------------
# Favicon Fingerprinting
# ----------------------------------------------------------------------

async def _check_favicon_fingerprint(
    client: httpx.AsyncClient, base_url: str
) -> list[tuple[str, str, PluginFinding]]:
    import hashlib

    response = await _safe_get(client, f"{base_url.rstrip('/')}/favicon.ico")

    if response is None or response.status_code != 200 or not response.content:
        return []

    content = response.content
    md5_hash = hashlib.md5(content).hexdigest()
    sha256_hash = hashlib.sha256(content).hexdigest()

    shodan_hash: int | None = None
    try:
        import base64

        import mmh3  # optional dependency; not installed by default

        encoded = base64.encodebytes(content)
        shodan_hash = mmh3.hash(encoded)
    except ImportError:
        pass

    evidence = f"MD5: {md5_hash}, SHA-256: {sha256_hash[:16]}..."
    if shodan_hash is not None:
        evidence += f", Shodan-style hash: {shodan_hash}"

    return [
        (
            "favicon-fingerprint",
            "Favicon Fingerprinting",
            PluginFinding(
                category="Information Disclosure",
                severity=Severity.INFORMATIONAL,
                confidence=Confidence.LOW,
                description=(
                    "The site's favicon hash was computed for technology "
                    "correlation (e.g. against Shodan or a known-icon database)."
                ),
                evidence=evidence,
                recommendation=(
                    "Informational only - no action needed unless the favicon "
                    "identifies a default/unbranded install of a known product "
                    "that should have been replaced or hardened."
                ),
                references=(
                    ["https://www.shodan.io/search?query=http.favicon.hash%3A" + str(shodan_hash)]
                    if shodan_hash is not None
                    else []
                ),
            ),
        )
    ]
