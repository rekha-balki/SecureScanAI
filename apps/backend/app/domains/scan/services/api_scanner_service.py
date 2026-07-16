"""
API Scan orchestration: executes a single (curl-derived) HTTP request
plus a small number of security probe variants, runs the relevant
subset of the plugin framework against the response(s), and persists
findings through the same pipeline as web scans (so PDF/Excel/JSON
export, compliance mapping, and DPDP mapping all work unchanged).
"""

from __future__ import annotations

import hashlib
import time
from datetime import UTC, datetime

import httpx

from app.domains.finding.domain.aggregates.finding import Finding
from app.domains.finding.repositories.finding_repository import FindingRepository
from app.domains.finding.services.cvss_service import estimate_cvss
from app.domains.notification.domain.enums import NotificationType
from app.domains.notification.services.notification_service import (
    NotificationService,
)
from app.domains.scan.domain.enums import ScanStatus
from app.domains.scan.repositories.scan_repository import ScanRepository
from app.domains.scan.services.api_plugins import (
    API_RESPONSE_PLUGINS,
    BrokenAuthEnforcementFinding,
)
from app.domains.scan.services.curl_parser import parse_curl
from app.domains.scan.services.plugin_base import PluginContext, PluginFinding
from app.domains.scan.services.plugins import PAGE_PLUGINS
from app.domains.scan.services.scanner_service import validate_target
from app.domains.scan.services.site_checks import (
    _check_cors_misconfiguration,
    _check_http_methods,
)
from app.platform import get_logger

logger = get_logger(__name__)

_REQUEST_TIMEOUT = 20.0
_CREDENTIAL_HEADERS = ("authorization", "cookie")


def _fingerprint(plugin_id: str, url: str, category: str, evidence: str) -> str:
    raw = f"{plugin_id}|{url}|{category}|{evidence}".encode()
    return hashlib.sha256(raw).hexdigest()


def _to_finding(
    scan_id: str, company_id: str, plugin_id: str, plugin_name: str,
    pf: PluginFinding, url: str, fingerprint: str,
) -> Finding:
    cvss_score, cvss_vector = estimate_cvss(pf.severity)

    return Finding(
        id=FindingRepository.new_id(),
        scan_id=scan_id,
        company_id=company_id,
        plugin_id=plugin_id,
        plugin_name=plugin_name,
        category=pf.category,
        severity=pf.severity,
        confidence=pf.confidence,
        affected_url=url,
        description=pf.description,
        evidence=pf.evidence,
        recommendation=pf.recommendation,
        business_impact=pf.business_impact,
        technical_impact=pf.technical_impact,
        references=pf.references,
        owasp_reference=pf.owasp_reference,
        cwe_reference=pf.cwe_reference,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        fingerprint=fingerprint,
    )


async def execute_api_scan(scan_id: str, company_id: str) -> None:
    """
    Executes a queued API scan. Mirrors scanner_service.execute_scan's
    structure (background task, failure recovery, notifications) but
    for a single parsed curl request instead of a multi-page crawl.
    """

    scan_repo = ScanRepository()
    finding_repo = FindingRepository()
    notifications = NotificationService()

    scan = await scan_repo.find_by_id(scan_id, company_id)

    if scan is None:
        logger.error("API scan %s not found for execution", scan_id)
        return

    try:
        await scan_repo.update_fields(
            scan_id,
            {"status": ScanStatus.RUNNING.value, "started_at": datetime.now(UTC)},
        )

        parsed = parse_curl(scan.curl_command or "")
        validate_target(parsed.url)

        await scan_repo.update_fields(scan_id, {"target_url": parsed.url})

        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.SCAN_STARTED,
            title="API scan started",
            message=f"Executing {parsed.method} {parsed.url}",
            scan_id=scan_id,
        )

        seen_fingerprints: set[str] = set()
        findings: list[Finding] = []
        plugins_executed = 0

        async with httpx.AsyncClient(max_redirects=5) as client:
            body_bytes = parsed.body.encode("utf-8") if parsed.body else None

            started = time.perf_counter()
            response = await client.request(
                parsed.method,
                parsed.url,
                headers=parsed.headers,
                content=body_bytes,
                timeout=_REQUEST_TIMEOUT,
                follow_redirects=True,
            )
            elapsed_ms = (time.perf_counter() - started) * 1000

            context = PluginContext(
                url=parsed.url,
                response=response,
                response_time_ms=elapsed_ms,
                is_https=parsed.url.startswith("https://"),
            )

            for plugin in [*PAGE_PLUGINS, *API_RESPONSE_PLUGINS]:
                plugins_executed += 1

                try:
                    plugin_findings = plugin.evaluate(context)
                except Exception:  # noqa: BLE001 - plugin isolation
                    logger.exception(
                        "Plugin %s failed on API scan %s", plugin.metadata.plugin_id, scan_id
                    )
                    continue

                for pf in plugin_findings:
                    fp = _fingerprint(plugin.metadata.plugin_id, parsed.url, pf.category, pf.evidence)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)
                    findings.append(
                        _to_finding(
                            scan_id, company_id, plugin.metadata.plugin_id,
                            plugin.metadata.name, pf, parsed.url, fp,
                        )
                    )

            # Site-level checks that make sense against a single endpoint.
            try:
                for plugin_id, plugin_name, pf in await _check_http_methods(client, parsed.url):
                    fp = _fingerprint(plugin_id, parsed.url, pf.category, pf.evidence)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)
                    plugins_executed += 1
                    findings.append(
                        _to_finding(scan_id, company_id, plugin_id, plugin_name, pf, parsed.url, fp)
                    )
            except Exception:  # noqa: BLE001
                logger.exception("HTTP methods check failed for API scan %s", scan_id)

            try:
                for plugin_id, plugin_name, pf in await _check_cors_misconfiguration(client, parsed.url):
                    fp = _fingerprint(plugin_id, parsed.url, pf.category, pf.evidence)
                    if fp in seen_fingerprints:
                        continue
                    seen_fingerprints.add(fp)
                    plugins_executed += 1
                    findings.append(
                        _to_finding(scan_id, company_id, plugin_id, plugin_name, pf, parsed.url, fp)
                    )
            except Exception:  # noqa: BLE001
                logger.exception("CORS check failed for API scan %s", scan_id)

            # Broken auth enforcement: only meaningful if the curl carried
            # credentials to begin with.
            cred_headers = {
                k: v for k, v in parsed.headers.items() if k.lower() in _CREDENTIAL_HEADERS
            }
            if cred_headers:
                try:
                    stripped_headers = {
                        k: v for k, v in parsed.headers.items() if k.lower() not in _CREDENTIAL_HEADERS
                    }
                    unauth_response = await client.request(
                        parsed.method,
                        parsed.url,
                        headers=stripped_headers,
                        content=body_bytes,
                        timeout=_REQUEST_TIMEOUT,
                        follow_redirects=True,
                    )
                    plugins_executed += 1

                    if response.status_code < 400 and unauth_response.status_code < 400:
                        pf = BrokenAuthEnforcementFinding.build_finding(
                            response.status_code, unauth_response.status_code
                        )
                        fp = _fingerprint(
                            BrokenAuthEnforcementFinding.metadata.plugin_id,
                            parsed.url, pf.category, pf.evidence,
                        )
                        if fp not in seen_fingerprints:
                            seen_fingerprints.add(fp)
                            findings.append(
                                _to_finding(
                                    scan_id, company_id,
                                    BrokenAuthEnforcementFinding.metadata.plugin_id,
                                    BrokenAuthEnforcementFinding.metadata.name,
                                    pf, parsed.url, fp,
                                )
                            )
                except httpx.HTTPError:
                    logger.warning("Unauthenticated probe request failed for API scan %s", scan_id)

        await finding_repo.bulk_create(findings)

        await scan_repo.update_fields(
            scan_id,
            {
                "status": ScanStatus.COMPLETED.value,
                "pages_discovered": 1,
                "pages_crawled": 1,
                "plugins_executed": plugins_executed,
                "findings_count": len(findings),
                "completed_at": datetime.now(UTC),
            },
        )

        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.SCAN_COMPLETED,
            title="API scan completed",
            message=f"{parsed.method} {parsed.url} finished with {len(findings)} finding(s).",
            scan_id=scan_id,
        )

        logger.info("API scan %s completed with %d findings", scan_id, len(findings))

    except Exception as exc:  # noqa: BLE001 - top-level failure recovery
        logger.exception("API scan %s failed", scan_id)

        await scan_repo.update_fields(
            scan_id,
            {
                "status": ScanStatus.FAILED.value,
                "error_message": str(exc)[:500],
                "completed_at": datetime.now(UTC),
            },
        )

        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.SCAN_FAILED,
            title="API scan failed",
            message=f"API scan failed: {str(exc)[:200]}",
            scan_id=scan_id,
        )
