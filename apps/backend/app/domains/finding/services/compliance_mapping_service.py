"""
Compliance framework mapping.

IMPORTANT: this is a general reference mapping from OWASP Top 10 (2021)
categories to commonly-cited controls in PCI-DSS v4.0, SOC 2 Trust
Services Criteria, and ISO/IEC 27001:2022 Annex A - intended to help
prioritize remediation and start a compliance conversation, not to
serve as a certified compliance assessment. Actual applicability
depends on your organization's scope, data classification, and a
qualified assessor's judgment.
"""

from __future__ import annotations

import re

from app.domains.finding.domain.aggregates.finding import Finding

_OWASP_PREFIX = re.compile(r"^(A\d{2}):2021")

# owasp category -> list of (framework, control_id, control_name)
_OWASP_TO_CONTROLS: dict[str, list[tuple[str, str, str]]] = {
    "A01": [
        ("PCI-DSS v4.0", "7.1", "Restrict access to system components by need-to-know"),
        ("SOC 2", "CC6.1", "Logical access security measures"),
        ("ISO 27001:2022", "A.8.3", "Information access restriction"),
    ],
    "A02": [
        ("PCI-DSS v4.0", "4.2", "Encrypt transmission of cardholder data"),
        ("SOC 2", "CC6.7", "Transmission and disposal of confidential data"),
        ("ISO 27001:2022", "A.8.24", "Use of cryptography"),
    ],
    "A03": [
        ("PCI-DSS v4.0", "6.2.4", "Prevent common software attacks (injection)"),
        ("SOC 2", "CC7.1", "Detection and prevention of security events"),
        ("ISO 27001:2022", "A.8.28", "Secure coding"),
    ],
    "A04": [
        ("PCI-DSS v4.0", "6.2.1", "Bespoke/custom software developed securely"),
        ("SOC 2", "CC8.1", "Change management"),
        ("ISO 27001:2022", "A.8.25", "Secure development life cycle"),
    ],
    "A05": [
        ("PCI-DSS v4.0", "2.2", "Secure configuration standards applied"),
        ("SOC 2", "CC6.1", "Logical access security measures"),
        ("ISO 27001:2022", "A.8.9", "Configuration management"),
    ],
    "A06": [
        ("PCI-DSS v4.0", "6.3.3", "Vulnerability and patch management"),
        ("SOC 2", "CC7.1", "Detection and prevention of security events"),
        ("ISO 27001:2022", "A.8.8", "Management of technical vulnerabilities"),
    ],
    "A07": [
        ("PCI-DSS v4.0", "8.3", "Strong authentication for users and administrators"),
        ("SOC 2", "CC6.1", "Logical access security measures"),
        ("ISO 27001:2022", "A.8.5", "Secure authentication"),
    ],
    "A08": [
        ("PCI-DSS v4.0", "6.5", "Software and data integrity in changes"),
        ("SOC 2", "CC7.1", "Detection and prevention of security events"),
        ("ISO 27001:2022", "A.8.28", "Secure coding"),
    ],
    "A09": [
        ("PCI-DSS v4.0", "10.2", "Audit logs implemented for all system components"),
        ("SOC 2", "CC7.2", "Monitoring of system components"),
        ("ISO 27001:2022", "A.8.15", "Logging"),
    ],
    "A10": [
        ("PCI-DSS v4.0", "6.2.4", "Prevent common software attacks (SSRF)"),
        ("SOC 2", "CC7.1", "Detection and prevention of security events"),
        ("ISO 27001:2022", "A.8.20", "Network security"),
    ],
}


def build_compliance_report(findings: list[Finding]) -> dict:
    """
    Groups findings under each mapped (framework, control) pair.
    A finding with no OWASP reference, or one outside the standard
    A01-A10:2021 categories, is grouped under "Unmapped".
    """

    grouped: dict[str, dict] = {}
    unmapped: list[Finding] = []

    for finding in findings:
        match = _OWASP_PREFIX.match(finding.owasp_reference or "")

        if not match:
            unmapped.append(finding)
            continue

        controls = _OWASP_TO_CONTROLS.get(match.group(1), [])

        if not controls:
            unmapped.append(finding)
            continue

        for framework, control_id, control_name in controls:
            key = f"{framework}::{control_id}"
            bucket = grouped.setdefault(
                key,
                {
                    "framework": framework,
                    "control_id": control_id,
                    "control_name": control_name,
                    "finding_ids": [],
                },
            )
            bucket["finding_ids"].append(finding.id)

    frameworks: dict[str, list[dict]] = {}
    for bucket in grouped.values():
        frameworks.setdefault(bucket["framework"], []).append(
            {
                "control_id": bucket["control_id"],
                "control_name": bucket["control_name"],
                "finding_count": len(bucket["finding_ids"]),
                "finding_ids": bucket["finding_ids"],
            }
        )

    for controls in frameworks.values():
        controls.sort(key=lambda c: c["control_id"])

    return {
        "frameworks": frameworks,
        "unmapped_finding_ids": [f.id for f in unmapped],
        "disclaimer": (
            "This mapping is a general reference to help prioritize remediation "
            "and is not a certified compliance assessment. Consult a qualified "
            "assessor for formal PCI-DSS/SOC 2/ISO 27001 scoping."
        ),
    }
