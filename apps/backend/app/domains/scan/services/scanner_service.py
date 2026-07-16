"""
Scan Manager / orchestration entry point (FRS Part 2 & Part 5).

Coordinates target validation, authentication, crawling, plugin
execution, active testing, finding persistence, and scan state
transitions. Runs as a background task so the API can return
immediately after queuing (FR-015).
"""

from __future__ import annotations

import hashlib
import socket
from datetime import UTC, datetime
from urllib.parse import parse_qs, urlparse

import httpx

from app.domains.finding.domain.aggregates.finding import Finding
from app.domains.finding.repositories.finding_repository import FindingRepository
from app.domains.finding.services.cvss_service import estimate_cvss
from app.domains.notification.domain.enums import NotificationType
from app.domains.notification.services.notification_service import (
    NotificationService,
)
from app.domains.organization.repositories.settings_repository import (
    SettingsRepository,
)
from app.domains.scan.domain.enums import ScanStatus
from app.domains.scan.repositories.attack_surface_repository import (
    AttackSurfaceRepository,
)
from app.domains.scan.repositories.scan_repository import ScanRepository
from app.domains.scan.services.active_testing_service import run_active_checks
from app.domains.scan.services.authentication_service import apply_authentication
from app.domains.scan.services.crawler_service import crawl
from app.domains.scan.services.plugin_base import PluginContext, PluginFinding
from app.domains.scan.services.plugins import PAGE_PLUGINS
from app.domains.scan.services.site_checks import run_site_checks
from app.platform import get_logger
from app.platform.errors.exceptions import ValidationException

logger = get_logger(__name__)

_MAX_REDIRECTS = 5


def validate_target(target_url: str) -> str:
    """
    Target Validation (FRS Section 22).
    """

    parsed = urlparse(target_url)

    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValidationException("Target must be a valid HTTP or HTTPS URL.")

    try:
        socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror as exc:
        raise ValidationException(
            f"Target host '{parsed.hostname}' could not be resolved."
        ) from exc

    return target_url


def _fingerprint(plugin_id: str, url: str, category: str, evidence: str) -> str:
    raw = f"{plugin_id}|{url}|{category}|{evidence}".encode()
    return hashlib.sha256(raw).hexdigest()


def _build_attack_surface(pages, forms) -> tuple[list[dict], list[dict], list[dict]]:
    """
    Reduces crawl output into a lightweight inventory: unique URLs,
    unique query parameters, and discovered forms (FRS Section 24).
    """

    urls = [{"url": url, "status_code": response.status_code} for url, response, _ in pages]

    seen_params: set[tuple[str, str]] = set()
    parameters: list[dict] = []

    for url, _response, _elapsed in pages:
        parsed = urlparse(url)
        if not parsed.query:
            continue

        for name in parse_qs(parsed.query, keep_blank_values=True):
            key = (parsed.path, name)
            if key in seen_params:
                continue
            seen_params.add(key)
            parameters.append({"url": url, "path": parsed.path, "name": name})

    form_docs = [
        {
            "page_url": f.page_url,
            "action_url": f.action_url,
            "method": f.method,
            "fields": f.fields,
        }
        for f in forms
    ]

    return urls, parameters, form_docs


async def execute_scan(scan_id: str, company_id: str) -> None:
    """
    Executes a queued scan end-to-end. Designed to run as a
    FastAPI BackgroundTask; failures are caught and recorded on the
    scan record rather than raised (FRS Section 119, Failure Recovery).
    """

    scan_repo = ScanRepository()
    finding_repo = FindingRepository()
    notifications = NotificationService()

    scan = await scan_repo.find_by_id(scan_id, company_id)

    if scan is None:
        logger.error("Scan %s not found for execution", scan_id)
        return

    try:
        await scan_repo.update_fields(
            scan_id,
            {"status": ScanStatus.RUNNING.value, "started_at": datetime.now(UTC)},
        )

        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.SCAN_STARTED,
            title="Scan started",
            message=f"Scanning {scan.target_url} has begun.",
            scan_id=scan_id,
        )

        company_settings = await SettingsRepository().get_or_create(company_id)
        request_delay_ms = company_settings.scanner_defaults.request_delay_ms
        enable_js_rendering = company_settings.scanner_defaults.enable_js_rendering

        seen_fingerprints: set[str] = set()
        findings: list[Finding] = []
        plugins_executed = 0
        pages: list = []

        async with httpx.AsyncClient(
            headers={"User-Agent": "SecureScanAI/1.0 (+authorized-assessment)"},
            max_redirects=_MAX_REDIRECTS,
        ) as client:
            await apply_authentication(client, scan.auth_config)

            crawl_result = await crawl(
                client,
                scan.target_url,
                scan.max_depth,
                scan.max_pages,
                request_delay_ms=request_delay_ms,
                enable_js_rendering=enable_js_rendering,
            )
            pages = crawl_result.pages

            await scan_repo.update_fields(
                scan_id,
                {
                    "pages_discovered": len(pages),
                    "pages_crawled": len(pages),
                },
            )

            urls, parameters, form_docs = _build_attack_surface(
                pages, crawl_result.forms
            )
            await AttackSurfaceRepository().save(
                scan_id, company_id, urls, parameters, form_docs
            )

            for url, response, elapsed_ms in pages:
                context = PluginContext(
                    url=url,
                    response=response,
                    response_time_ms=elapsed_ms,
                    is_https=url.startswith("https://"),
                )

                for plugin in PAGE_PLUGINS:
                    plugins_executed += 1

                    try:
                        plugin_findings = plugin.evaluate(context)
                    except Exception:  # noqa: BLE001 - plugin isolation
                        logger.exception(
                            "Plugin %s failed on %s", plugin.metadata.plugin_id, url
                        )
                        continue

                    for pf in plugin_findings:
                        fp = _fingerprint(
                            plugin.metadata.plugin_id, url, pf.category, pf.evidence
                        )

                        if fp in seen_fingerprints:
                            continue

                        seen_fingerprints.add(fp)

                        findings.append(
                            _to_finding_entity(
                                scan_id, company_id, plugin.metadata, pf, url, fp
                            )
                        )

            try:
                site_results = await run_site_checks(client, scan.target_url)
            except Exception:  # noqa: BLE001 - plugin isolation
                logger.exception("Site-level checks failed for scan %s", scan_id)
                site_results = []

            for plugin_id, plugin_name, pf in site_results:
                fp = _fingerprint(plugin_id, scan.target_url, pf.category, pf.evidence)

                if fp in seen_fingerprints:
                    continue

                seen_fingerprints.add(fp)
                plugins_executed += 1

                findings.append(
                    _to_finding_entity_from_ids(
                        scan_id,
                        company_id,
                        plugin_id,
                        plugin_name,
                        pf,
                        scan.target_url,
                        fp,
                    )
                )

            try:
                active_results = await run_active_checks(
                    client, pages, crawl_result.forms
                )
            except Exception:  # noqa: BLE001 - active testing isolation
                logger.exception("Active testing failed for scan %s", scan_id)
                active_results = []

            for plugin_id, plugin_name, pf, affected_url in active_results:
                fp = _fingerprint(plugin_id, affected_url, pf.category, pf.evidence)

                if fp in seen_fingerprints:
                    continue

                seen_fingerprints.add(fp)
                plugins_executed += 1

                findings.append(
                    _to_finding_entity_from_ids(
                        scan_id,
                        company_id,
                        plugin_id,
                        plugin_name,
                        pf,
                        affected_url,
                        fp,
                    )
                )

        await finding_repo.bulk_create(findings)

        await scan_repo.update_fields(
            scan_id,
            {
                "status": ScanStatus.COMPLETED.value,
                "plugins_executed": plugins_executed,
                "findings_count": len(findings),
                "completed_at": datetime.now(UTC),
            },
        )

        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.SCAN_COMPLETED,
            title="Scan completed",
            message=(
                f"Scan of {scan.target_url} finished with {len(findings)} "
                f"finding(s). The report is ready to download."
            ),
            scan_id=scan_id,
        )
        await notifications.notify(
            company_id=company_id,
            user_id=scan.owner_id,
            type=NotificationType.REPORT_READY,
            title="Report ready",
            message=f"The PDF report for '{scan.name}' is ready to download.",
            scan_id=scan_id,
        )

        logger.info(
            "Scan %s completed: %d pages, %d findings",
            scan_id,
            len(pages),
            len(findings),
        )

    except Exception as exc:  # noqa: BLE001 - top-level failure recovery
        logger.exception("Scan %s failed", scan_id)

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
            title="Scan failed",
            message=f"Scan of {scan.target_url} failed: {str(exc)[:200]}",
            scan_id=scan_id,
        )


def _to_finding_entity(
    scan_id: str,
    company_id: str,
    metadata,
    pf: PluginFinding,
    url: str,
    fingerprint: str,
) -> Finding:
    return _to_finding_entity_from_ids(
        scan_id, company_id, metadata.plugin_id, metadata.name, pf, url, fingerprint
    )


def _to_finding_entity_from_ids(
    scan_id: str,
    company_id: str,
    plugin_id: str,
    plugin_name: str,
    pf: PluginFinding,
    url: str,
    fingerprint: str,
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
