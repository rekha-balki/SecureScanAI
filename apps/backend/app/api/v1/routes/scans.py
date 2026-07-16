"""
Scan management routes (FRS Part 2, Part 5, Section 8-10).
"""

import io

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from fastapi.responses import StreamingResponse

from app.domains.audit.domain.enums import AuditAction
from app.domains.audit.services.audit_service import AuditService, client_ip
from app.domains.finding.domain.enums import FindingStatus
from app.domains.finding.repositories.finding_repository import FindingRepository
from app.domains.finding.services.compliance_mapping_service import (
    build_compliance_report,
)
from app.domains.finding.services.dpdp_mapping_service import build_dpdp_report
from app.domains.identity.domain.aggregates.user import User
from app.domains.notification.domain.enums import NotificationType
from app.domains.notification.services.notification_service import (
    NotificationService,
)
from app.domains.organization.repositories.company_repository import (
    CompanyRepository,
)
from app.domains.report.services.export_service import (
    generate_findings_excel,
    generate_findings_json,
)
from app.domains.report.services.report_service import generate_scan_report_pdf
from app.domains.scan.domain.aggregates.scan import Scan
from app.domains.scan.domain.enums import ScanStatus, ScanType
from app.domains.scan.repositories.attack_surface_repository import (
    AttackSurfaceRepository,
)
from app.domains.scan.repositories.scan_repository import ScanRepository
from app.domains.scan.schemas import (
    CreateScanRequest,
    FindingResponse,
    ScanResponse,
    UpdateFindingRequest,
)
from app.domains.scan.services.api_scanner_service import execute_api_scan
from app.domains.scan.services.comparison_service import compare_findings
from app.domains.scan.services.curl_parser import parse_curl
from app.domains.scan.services.scanner_service import execute_scan, validate_target
from app.platform import get_logger
from app.platform.errors.exceptions import (
    ResourceNotFoundException,
    ValidationException,
)
from app.platform.security.dependencies import get_current_user
from app.shared.kernel.responses import ResponseBuilder

scans_router = APIRouter(prefix="/scans", tags=["Scans"])

logger = get_logger(__name__)


def _to_scan_response(scan: Scan) -> dict:
    return ScanResponse(
        id=scan.id,
        name=scan.name,
        scan_type=scan.scan_type,
        target_url=scan.target_url,
        description=scan.description,
        status=scan.status,
        priority=scan.priority,
        max_depth=scan.max_depth,
        max_pages=scan.max_pages,
        pages_discovered=scan.pages_discovered,
        pages_crawled=scan.pages_crawled,
        plugins_executed=scan.plugins_executed,
        findings_count=scan.findings_count,
        error_message=scan.error_message,
        has_auth=bool(scan.auth_config and scan.auth_config.get("type") not in (None, "none")),
        created_at=scan.created_at,
        started_at=scan.started_at,
        completed_at=scan.completed_at,
    ).model_dump()


def _to_finding_response(f) -> dict:
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        plugin_id=f.plugin_id,
        plugin_name=f.plugin_name,
        category=f.category,
        severity=f.severity.value,
        confidence=f.confidence.value,
        affected_url=f.affected_url,
        description=f.description,
        evidence=f.evidence,
        recommendation=f.recommendation,
        business_impact=f.business_impact,
        technical_impact=f.technical_impact,
        owasp_reference=f.owasp_reference,
        cwe_reference=f.cwe_reference,
        cvss_score=f.cvss_score,
        cvss_vector=f.cvss_vector,
        status=f.status.value,
        assigned_user_id=f.assigned_user_id,
        created_at=f.created_at,
    ).model_dump()


async def _queue_scan(scan: Scan, background_tasks: BackgroundTasks) -> None:
    await ScanRepository().create(scan)

    if scan.scan_type == ScanType.API:
        background_tasks.add_task(execute_api_scan, scan.id, scan.company_id)
    else:
        background_tasks.add_task(execute_scan, scan.id, scan.company_id)


@scans_router.post("", summary="Create and queue a new scan (web crawl or single-request API scan)")
async def create_scan(
    payload: CreateScanRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    if payload.scan_type == ScanType.API:
        # Parse eagerly so a malformed curl command fails fast with a
        # clear 400 instead of queuing a scan that immediately fails.
        parsed = parse_curl(payload.curl_command or "")
        validate_target(parsed.url)
        target_url = parsed.url
    else:
        validate_target(payload.target_url)
        target_url = payload.target_url

    scan = Scan(
        id=ScanRepository.new_id(),
        company_id=current_user.company_id,
        owner_id=current_user.id,
        name=payload.name,
        scan_type=payload.scan_type,
        target_url=target_url,
        curl_command=payload.curl_command if payload.scan_type == ScanType.API else None,
        description=payload.description,
        max_depth=payload.max_depth,
        max_pages=payload.max_pages,
        priority=payload.priority,
        status=ScanStatus.QUEUED,
        auth_config=payload.auth_config.model_dump() if payload.auth_config else None,
    )

    await _queue_scan(scan, background_tasks)

    logger.info("Scan queued: %s (%s) -> %s", scan.id, scan.scan_type.value, scan.target_url)

    await AuditService().record(
        AuditAction.SCAN_SUBMITTED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=scan.id,
        ip_address=client_ip(request),
        details=scan.target_url,
    )

    return ResponseBuilder.success("Scan queued.", _to_scan_response(scan))


@scans_router.get("", summary="List scans for the current company")
async def list_scans(current_user: User = Depends(get_current_user)):
    scans = await ScanRepository().list_by_company(current_user.company_id)

    return ResponseBuilder.success(
        "Scans retrieved.", [_to_scan_response(s) for s in scans]
    )


@scans_router.get("/{scan_id}", summary="Get scan details")
async def get_scan(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    return ResponseBuilder.success("Scan retrieved.", _to_scan_response(scan))


@scans_router.post("/{scan_id}/cancel", summary="Cancel a scan")
async def cancel_scan(
    scan_id: str, request: Request, current_user: User = Depends(get_current_user)
):
    repo = ScanRepository()
    scan = await repo.find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    if scan.status in (ScanStatus.COMPLETED, ScanStatus.CANCELLED, ScanStatus.FAILED):
        raise ValidationException(
            f"Scan cannot be cancelled from status '{scan.status.value}'."
        )

    await repo.update_fields(scan_id, {"status": ScanStatus.CANCELLED.value})

    await AuditService().record(
        AuditAction.SCAN_CANCELLED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=scan_id,
        ip_address=client_ip(request),
    )

    await NotificationService().notify(
        company_id=current_user.company_id,
        user_id=scan.owner_id,
        type=NotificationType.SCAN_CANCELLED,
        title="Scan cancelled",
        message=f"Scan of {scan.target_url} was cancelled.",
        scan_id=scan_id,
    )

    return ResponseBuilder.success("Scan cancelled.", {"id": scan_id})


@scans_router.delete("/{scan_id}", summary="Delete a scan (FR-019)")
async def delete_scan(
    scan_id: str, request: Request, current_user: User = Depends(get_current_user)
):
    repo = ScanRepository()
    scan = await repo.find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    if scan.status not in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        raise ValidationException(
            "Only scans in the Completed or Cancelled state can be deleted "
            f"(current status: '{scan.status.value}')."
        )

    await FindingRepository().delete_by_scan(scan_id, current_user.company_id)
    await repo.delete_by_id(scan_id, current_user.company_id)

    await AuditService().record(
        AuditAction.SCAN_DELETED,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=scan_id,
        ip_address=client_ip(request),
        details=scan.target_url,
    )

    return ResponseBuilder.success("Scan deleted.", {"id": scan_id})


@scans_router.post("/{scan_id}/rerun", summary="Re-run a scan with the same configuration (FR-019)")
async def rerun_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    original = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if original is None:
        raise ResourceNotFoundException("Scan not found.")

    new_scan = Scan(
        id=ScanRepository.new_id(),
        company_id=current_user.company_id,
        owner_id=current_user.id,
        name=f"{original.name} (re-run)",
        scan_type=original.scan_type,
        target_url=original.target_url,
        curl_command=original.curl_command,
        description=original.description,
        max_depth=original.max_depth,
        max_pages=original.max_pages,
        priority=original.priority,
        status=ScanStatus.QUEUED,
        auth_config=original.auth_config,
    )

    await _queue_scan(new_scan, background_tasks)

    await AuditService().record(
        AuditAction.SCAN_RERUN,
        company_id=current_user.company_id,
        user_id=current_user.id,
        target=new_scan.id,
        ip_address=client_ip(request),
        details=f"rerun of {scan_id}",
    )

    return ResponseBuilder.success("Scan queued.", _to_scan_response(new_scan))


@scans_router.get("/{scan_id}/findings", summary="List findings for a scan")
async def list_findings(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)

    return ResponseBuilder.success(
        "Findings retrieved.", [_to_finding_response(f) for f in findings]
    )


@scans_router.patch(
    "/{scan_id}/findings/{finding_id}",
    summary="Update a finding's status or assignment",
)
async def update_finding(
    scan_id: str,
    finding_id: str,
    payload: UpdateFindingRequest,
    current_user: User = Depends(get_current_user),
):
    repo = FindingRepository()

    finding = await repo.find_by_id(finding_id, current_user.company_id)

    if finding is None or finding.scan_id != scan_id:
        raise ResourceNotFoundException("Finding not found.")

    status = None
    if payload.status is not None:
        try:
            status = FindingStatus(payload.status)
        except ValueError as exc:
            valid = ", ".join(s.value for s in FindingStatus)
            raise ValidationException(
                f"Invalid status '{payload.status}'. Valid values: {valid}."
            ) from exc

    await repo.update_status_and_assignee(
        finding_id, current_user.company_id, status, payload.assigned_user_id
    )

    notifications = NotificationService()

    if payload.assigned_user_id:
        await notifications.notify(
            company_id=current_user.company_id,
            user_id=payload.assigned_user_id,
            type=NotificationType.ASSIGNMENT,
            title="Finding assigned to you",
            message=f"{finding.plugin_name}: {finding.description[:120]}",
            scan_id=scan_id,
            finding_id=finding_id,
        )

    if status is not None:
        notify_target = payload.assigned_user_id or finding.assigned_user_id
        if notify_target:
            await notifications.notify(
                company_id=current_user.company_id,
                user_id=notify_target,
                type=NotificationType.FINDING_UPDATED,
                title="Finding status updated",
                message=f"{finding.plugin_name} is now '{status.value}'.",
                scan_id=scan_id,
                finding_id=finding_id,
            )

    updated = await repo.find_by_id(finding_id, current_user.company_id)

    return ResponseBuilder.success("Finding updated.", _to_finding_response(updated))


@scans_router.get(
    "/{scan_id}/compare/{baseline_scan_id}",
    summary="Compare this scan's findings against an earlier scan of the same target",
)
async def compare_scans(
    scan_id: str,
    baseline_scan_id: str,
    current_user: User = Depends(get_current_user),
):
    scan_repo = ScanRepository()
    finding_repo = FindingRepository()

    current_scan = await scan_repo.find_by_id(scan_id, current_user.company_id)
    baseline_scan = await scan_repo.find_by_id(baseline_scan_id, current_user.company_id)

    if current_scan is None or baseline_scan is None:
        raise ResourceNotFoundException("One or both scans were not found.")

    current_findings = await finding_repo.list_by_scan(scan_id, current_user.company_id)
    baseline_findings = await finding_repo.list_by_scan(
        baseline_scan_id, current_user.company_id
    )

    diff = compare_findings(baseline_findings, current_findings)

    return ResponseBuilder.success(
        "Comparison computed.",
        {
            "current_scan_id": scan_id,
            "baseline_scan_id": baseline_scan_id,
            "same_target": current_scan.target_url == baseline_scan.target_url,
            "new_count": len(diff["new"]),
            "fixed_count": len(diff["fixed"]),
            "persistent_count": len(diff["persistent"]),
            "new": [_to_finding_response(f) for f in diff["new"]],
            "fixed": [_to_finding_response(f) for f in diff["fixed"]],
            "persistent": [_to_finding_response(f) for f in diff["persistent"]],
        },
    )


@scans_router.get(
    "/{scan_id}/compliance-mapping",
    summary="Map this scan's findings to PCI-DSS/SOC 2/ISO 27001 controls (reference only)",
)
async def get_compliance_mapping(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)
    report = build_compliance_report(findings)

    return ResponseBuilder.success("Compliance mapping computed.", report)


@scans_router.get(
    "/{scan_id}/dpdp-mapping",
    summary="Map this scan's findings to India's DPDP Act, 2023 (reference only)",
)
async def get_dpdp_mapping(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)
    report = build_dpdp_report(findings)

    return ResponseBuilder.success("DPDP mapping computed.", report)


@scans_router.get("/{scan_id}/attack-surface", summary="Get discovered URLs, parameters, and forms")
async def get_attack_surface(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    surface = await AttackSurfaceRepository().find_by_scan(scan_id, current_user.company_id)

    if surface is None:
        return ResponseBuilder.success(
            "Attack surface retrieved.",
            {"urls": [], "parameters": [], "forms": []},
        )

    return ResponseBuilder.success(
        "Attack surface retrieved.",
        {
            "urls": surface.get("urls", []),
            "parameters": surface.get("parameters", []),
            "forms": surface.get("forms", []),
        },
    )


@scans_router.get("/{scan_id}/report", summary="Download the PDF report")
async def download_report(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)

    company = await CompanyRepository().find_by_id(current_user.company_id)
    company_name = company.name if company else "Unknown Company"

    pdf_bytes = generate_scan_report_pdf(scan, findings, company_name)

    filename = f"securescan-report-{scan.id}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@scans_router.get("/{scan_id}/export/json", summary="Export findings as JSON")
async def export_json(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)
    payload = generate_findings_json(scan, findings)

    return StreamingResponse(
        io.BytesIO(payload),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="securescan-{scan.id}.json"'
        },
    )


@scans_router.get("/{scan_id}/export/excel", summary="Export findings as an Excel workbook")
async def export_excel(scan_id: str, current_user: User = Depends(get_current_user)):
    scan = await ScanRepository().find_by_id(scan_id, current_user.company_id)

    if scan is None:
        raise ResourceNotFoundException("Scan not found.")

    findings = await FindingRepository().list_by_scan(scan_id, current_user.company_id)
    workbook_bytes = generate_findings_excel(scan, findings)

    return StreamingResponse(
        io.BytesIO(workbook_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={
            "Content-Disposition": f'attachment; filename="securescan-{scan.id}.xlsx"'
        },
    )
