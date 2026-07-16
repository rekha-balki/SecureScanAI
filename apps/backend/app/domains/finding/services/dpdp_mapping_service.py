"""
DPDP (India's Digital Personal Data Protection Act, 2023) mapping.

IMPORTANT: like compliance_mapping_service.py, this is a general
reference mapping from technical finding categories to DPDP provisions
most commonly implicated by that class of issue - primarily Section
8(5) ("reasonable security safeguards to prevent personal data
breach"), which is where nearly all technical security findings land
under this Act. It is not a legal opinion, not a Data Protection
Impact Assessment, and does not determine whether your organization is
a Data Fiduciary or Significant Data Fiduciary under the Act. Consult
counsel/a qualified assessor for an actual DPDP compliance review.
"""

from __future__ import annotations

from app.domains.finding.domain.aggregates.finding import Finding

_SECTION_8_5 = (
    "Section 8(5)",
    "Reasonable security safeguards to prevent personal data breach",
)
_SECTION_8_1 = (
    "Section 8(1)",
    "Process personal data only for the specified/lawful purpose (data minimization)",
)
_SECTION_8_4 = (
    "Section 8(4)",
    "Data Fiduciary remains responsible for processing carried out by/for it",
)

_PII_PLUGIN_IDS = {"dpdp-personal-data-exposure", "sensitive-data-exposure"}

_TRANSPORT_CWES = {"CWE-319", "CWE-326", "CWE-295", "CWE-327"}

_AUTH_PLUGIN_IDS = {"api-broken-auth-enforcement"}


def _sections_for(finding: Finding) -> list[tuple[str, str]]:
    sections: list[tuple[str, str]] = []

    if finding.plugin_id in _PII_PLUGIN_IDS:
        sections.append(_SECTION_8_5)
        sections.append(_SECTION_8_1)
    elif finding.plugin_id in _AUTH_PLUGIN_IDS:
        sections.append(_SECTION_8_5)
        sections.append(_SECTION_8_4)
    elif finding.cwe_reference in _TRANSPORT_CWES:
        sections.append(_SECTION_8_5)
    elif finding.category in (
        "Information Disclosure",
        "Configuration Issues",
        "Authentication Indicators",
        "Authorization Indicators",
        "Cookies",
    ):
        sections.append(_SECTION_8_5)

    return sections


def build_dpdp_report(findings: list[Finding]) -> dict:
    grouped: dict[str, dict] = {}
    unmapped: list[Finding] = []

    for finding in findings:
        sections = _sections_for(finding)

        if not sections:
            unmapped.append(finding)
            continue

        for section_id, section_desc in sections:
            bucket = grouped.setdefault(
                section_id,
                {"section": section_id, "description": section_desc, "finding_ids": []},
            )
            bucket["finding_ids"].append(finding.id)

    sections_out = sorted(grouped.values(), key=lambda b: b["section"])
    for bucket in sections_out:
        bucket["finding_count"] = len(bucket["finding_ids"])

    personal_data_findings = [
        f.id for f in findings if f.plugin_id in _PII_PLUGIN_IDS
    ]

    return {
        "sections": sections_out,
        "personal_data_finding_ids": personal_data_findings,
        "unmapped_finding_ids": [f.id for f in unmapped],
        "disclaimer": (
            "This mapping highlights DPDP, 2023 provisions commonly implicated "
            "by each finding - primarily Section 8(5)'s security-safeguards "
            "duty - to help prioritize remediation. It is not a legal opinion "
            "or a substitute for a formal DPDP compliance assessment."
        ),
    }
