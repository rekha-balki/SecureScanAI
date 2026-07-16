"""
Lightweight active testing (Tier 3).

Unlike the passive plugins in plugins.py / site_checks.py, these checks
send a mutated request and inspect the response for a specific signal.
This is deliberately narrow - a handful of well-understood, low-risk
probes against parameters already discovered during crawl - not a
general-purpose fuzzing engine. Each probe is a single GET (or the
form's declared method) with one parameter perturbed; nothing here
attempts to write, delete, or modify data on the target beyond what an
ordinary GET request already implies.

Coverage is intentionally capped (see _MAX_PARAMETER_TESTS) to keep
scan duration and target load bounded.
"""

from __future__ import annotations

import secrets
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from app.domains.finding.domain.enums import Confidence, Severity
from app.domains.scan.services.crawler_service import DiscoveredForm
from app.domains.scan.services.plugin_base import PluginFinding

_MAX_PARAMETER_TESTS = 40
_REQUEST_TIMEOUT = 10.0

_REDIRECT_PARAM_NAMES = {
    "redirect",
    "redirect_uri",
    "redirect_url",
    "url",
    "next",
    "return",
    "return_url",
    "returnto",
    "continue",
    "dest",
    "destination",
    "target",
    "callback",
    "go",
}

_SQL_ERROR_SIGNATURES = (
    ("MySQL", "you have an error in your sql syntax"),
    ("MySQL", "warning: mysql"),
    ("MySQL", "mysqli_"),
    ("PostgreSQL", "pg_query()"),
    ("PostgreSQL", "postgresql query failed"),
    ("PostgreSQL", "unterminated quoted string"),
    ("MSSQL", "unclosed quotation mark"),
    ("MSSQL", "microsoft ole db provider for sql server"),
    ("MSSQL", "microsoft odbc sql server driver"),
    ("Oracle", "ora-01756"),
    ("Oracle", "ora-00933"),
    ("SQLite", "sqlite3.operationalerror"),
    ("SQLite", "sqlite_query"),
    ("Generic", "sql syntax"),
    ("Generic", "syntax error in sql statement"),
)

_EXTERNAL_TEST_HOST = "ssai-redirect-probe.invalid"


def _candidate_url_params(
    pages: list[tuple[str, httpx.Response, float]],
) -> list[tuple[str, str, str]]:
    """
    Returns (url, param_name, original_value) tuples for every unique
    query parameter observed across crawled URLs, capped to
    _MAX_PARAMETER_TESTS.
    """

    seen: set[tuple[str, str]] = set()
    candidates: list[tuple[str, str, str]] = []

    for url, _response, _elapsed in pages:
        parsed = urlparse(url)
        if not parsed.query:
            continue

        params = parse_qs(parsed.query, keep_blank_values=True)

        for name, values in params.items():
            key = (parsed.path, name)
            if key in seen:
                continue
            seen.add(key)

            candidates.append((url, name, values[0] if values else ""))

            if len(candidates) >= _MAX_PARAMETER_TESTS:
                return candidates

    return candidates


def _build_mutated_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    params = parse_qs(parsed.query, keep_blank_values=True)
    params[param] = [value]
    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


async def run_active_checks(
    client: httpx.AsyncClient,
    pages: list[tuple[str, httpx.Response, float]],
    forms: list[DiscoveredForm],
) -> list[tuple[str, str, PluginFinding, str]]:
    """
    Returns (plugin_id, plugin_name, finding, affected_url) tuples.
    """

    results: list[tuple[str, str, PluginFinding, str]] = []
    candidates = _candidate_url_params(pages)

    for url, param, original_value in candidates:
        xss_finding = await _test_reflected_xss(client, url, param)
        if xss_finding:
            results.append(xss_finding)

        sqli_finding = await _test_error_based_sqli(client, url, param, original_value)
        if sqli_finding:
            results.append(sqli_finding)

        if param.lower() in _REDIRECT_PARAM_NAMES:
            redirect_finding = await _test_open_redirect(client, url, param)
            if redirect_finding:
                results.append(redirect_finding)

    for form in forms:
        if form.method != "GET" or not form.fields:
            continue
        # GET-method forms behave like query-parameter endpoints; a
        # subset of their declared fields are worth a quick XSS probe
        # even if the crawler never happened to see them populated.
        for field_name in form.fields[:3]:
            mutated = _build_mutated_url(form.action_url, field_name, "")
            xss_finding = await _test_reflected_xss(client, mutated, field_name)
            if xss_finding:
                results.append(xss_finding)

    return results


async def _safe_get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
    try:
        return await client.get(
            url, timeout=_REQUEST_TIMEOUT, follow_redirects=False
        )
    except httpx.HTTPError:
        return None


async def _test_reflected_xss(
    client: httpx.AsyncClient, url: str, param: str
) -> tuple[str, str, PluginFinding, str] | None:
    marker = f"ssai{secrets.token_hex(4)}xss"
    probe_value = f"<{marker}>"
    probe_url = _build_mutated_url(url, param, probe_value)

    response = await _safe_get(client, probe_url)
    if response is None:
        return None

    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type:
        return None

    body = response.text
    if probe_value in body:
        return (
            "active-reflected-xss",
            "Reflected Cross-Site Scripting",
            PluginFinding(
                category="Input Validation Indicators",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                description=(
                    f"Parameter '{param}' reflects an injected HTML tag unescaped "
                    "in the response, indicating likely reflected XSS."
                ),
                evidence=f"Requested {param}={probe_value!r}; response body contains the unescaped tag.",
                recommendation=(
                    "HTML-encode all user-controlled output at the point of "
                    "rendering, and apply a restrictive Content-Security-Policy "
                    "as defense-in-depth."
                ),
                technical_impact="An attacker-controlled script could execute in victims' browsers.",
                owasp_reference="A03:2021 - Injection",
                cwe_reference="CWE-79",
            ),
            probe_url,
        )

    return None


async def _test_error_based_sqli(
    client: httpx.AsyncClient, url: str, param: str, original_value: str
) -> tuple[str, str, PluginFinding, str] | None:
    probe_value = f"{original_value}'"
    probe_url = _build_mutated_url(url, param, probe_value)

    response = await _safe_get(client, probe_url)
    if response is None:
        return None

    content_type = response.headers.get("content-type", "")
    if "text/html" not in content_type and "json" not in content_type:
        return None

    body_lower = response.text.lower()

    for engine, signature in _SQL_ERROR_SIGNATURES:
        if signature in body_lower:
            return (
                "active-sqli-error-based",
                "SQL Injection (Error-Based)",
                PluginFinding(
                    category="Input Validation Indicators",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Parameter '{param}' triggers a {engine} error when a "
                        "single quote is appended, indicating likely SQL injection."
                    ),
                    evidence=f"Requested {param}={probe_value!r}; response contains a {engine} error signature.",
                    recommendation=(
                        "Use parameterized queries / prepared statements for all "
                        "database access; never concatenate user input into SQL."
                    ),
                    technical_impact="An attacker may read, modify, or delete database contents.",
                    owasp_reference="A03:2021 - Injection",
                    cwe_reference="CWE-89",
                ),
                probe_url,
            )

    return None


async def _test_open_redirect(
    client: httpx.AsyncClient, url: str, param: str
) -> tuple[str, str, PluginFinding, str] | None:
    probe_target = f"https://{_EXTERNAL_TEST_HOST}/"
    probe_url = _build_mutated_url(url, param, probe_target)

    response = await _safe_get(client, probe_url)
    if response is None or response.status_code not in (301, 302, 303, 307, 308):
        return None

    location = response.headers.get("location", "")

    if _EXTERNAL_TEST_HOST in location:
        return (
            "active-open-redirect",
            "Open Redirection",
            PluginFinding(
                category="Input Validation Indicators",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                description=(
                    f"Parameter '{param}' controls the redirect target without "
                    "validating it against an allowlist."
                ),
                evidence=f"Requested {param}={probe_target!r}; response redirected to Location: {location}",
                recommendation=(
                    "Validate redirect targets against an allowlist of known-safe "
                    "paths/domains, or use indirect reference tokens instead of "
                    "raw URLs."
                ),
                technical_impact="Attacker-controlled redirects can be used in phishing campaigns.",
                owasp_reference="A01:2021 - Broken Access Control",
                cwe_reference="CWE-601",
            ),
            probe_url,
        )

    return None
