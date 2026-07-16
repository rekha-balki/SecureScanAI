"""
PDF report generation (FRS Section 11 / FRS Part 2 Section 45).
"""

from __future__ import annotations

import io
from collections import Counter
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.domains.finding.domain.aggregates.finding import Finding
from app.domains.scan.domain.aggregates.scan import Scan

_SEVERITY_COLORS = {
    "critical": "#B91C1C",
    "high": "#EA580C",
    "medium": "#CA8A04",
    "low": "#2563EB",
    "informational": "#64748B",
}

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"]


def generate_scan_report_pdf(
    scan: Scan, findings: list[Finding], company_name: str
) -> bytes:
    """
    Builds an executive + technical PDF report for a completed scan.
    """

    buffer = io.BytesIO()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        topMargin=20 * mm,
        bottomMargin=18 * mm,
        leftMargin=18 * mm,
        rightMargin=18 * mm,
        title=f"SecureScan AI Report - {scan.name}",
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "SSTitle", parent=styles["Title"], textColor=colors.HexColor("#0F172A")
    )
    h2 = ParagraphStyle(
        "SSHeading2", parent=styles["Heading2"], textColor=colors.HexColor("#0F172A")
    )
    body = styles["BodyText"]

    story = []

    story.append(Paragraph("SecureScan AI - Security Assessment Report", title_style))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(f"<b>Company:</b> {company_name}", body))
    story.append(Paragraph(f"<b>Scan Name:</b> {scan.name}", body))
    story.append(Paragraph(f"<b>Target:</b> {scan.target_url}", body))
    story.append(
        Paragraph(f"<b>Generated:</b> {datetime.utcnow().isoformat()}Z", body)
    )
    story.append(Spacer(1, 6 * mm))

    counts = Counter(f.severity.value for f in findings)

    story.append(Paragraph("Executive Summary", h2))
    story.append(
        Paragraph(
            f"This assessment discovered {len(findings)} finding(s) across "
            f"{scan.pages_crawled} page(s) of {scan.target_url}. The table below "
            f"summarizes findings by severity.",
            body,
        )
    )
    story.append(Spacer(1, 3 * mm))

    summary_data = [["Severity", "Count"]] + [
        [severity.title(), str(counts.get(severity, 0))]
        for severity in _SEVERITY_ORDER
    ]

    summary_table = Table(summary_data, colWidths=[80 * mm, 30 * mm])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0F172A")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
            ]
        )
    )
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    story.append(Paragraph("Technical Findings", h2))
    story.append(
        Paragraph(
            "<i>CVSS scores below are estimated from each finding's severity "
            "band, not individually calculated - treat them as a starting "
            "point for triage, not an authoritative score.</i>",
            body,
        )
    )
    story.append(Spacer(1, 2 * mm))

    ordered = sorted(
        findings, key=lambda f: _SEVERITY_ORDER.index(f.severity.value)
    )

    if not ordered:
        story.append(Paragraph("No findings were identified during this scan.", body))

    for finding in ordered:
        color_hex = _SEVERITY_COLORS.get(finding.severity.value, "#64748B")

        block = [
            Paragraph(
                f'<font color="{color_hex}"><b>[{finding.severity.value.upper()}]</b></font> '
                f"{finding.description}",
                h2,
            ),
            Paragraph(f"<b>Category:</b> {finding.category}", body),
            Paragraph(f"<b>Affected URL:</b> {finding.affected_url}", body),
            Paragraph(f"<b>Confidence:</b> {finding.confidence.value.title()}", body),
            Paragraph(f"<b>Evidence:</b> {finding.evidence}", body),
            Paragraph(f"<b>Recommendation:</b> {finding.recommendation}", body),
        ]

        if finding.owasp_reference:
            block.append(Paragraph(f"<b>OWASP:</b> {finding.owasp_reference}", body))
        if finding.cwe_reference:
            block.append(Paragraph(f"<b>CWE:</b> {finding.cwe_reference}", body))
        if finding.cvss_score is not None:
            block.append(
                Paragraph(
                    f"<b>CVSS (estimated):</b> {finding.cvss_score} "
                    f"({finding.cvss_vector})",
                    body,
                )
            )

        block.append(Spacer(1, 5 * mm))

        story.append(KeepTogether(block))

    doc.build(story)

    return buffer.getvalue()
