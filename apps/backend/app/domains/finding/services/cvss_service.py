"""
CVSS score estimation (FRS Section 10 / Part 3 Section 56).

IMPORTANT - this is a heuristic approximation, not a real CVSS
calculation. A true CVSS 3.1 score requires per-vulnerability judgment
across 8 base metrics (attack vector, complexity, privileges required,
user interaction, scope, and the confidentiality/integrity/availability
impact triad) that only a human analyst - or a much more specific
plugin - can determine accurately. What this module does instead is
map each finding's severity (already assigned by its plugin) to a
representative score/vector in the right neighborhood, so reports have
*something* CVSS-shaped to show and sort by, while being explicit in
the UI/report that these are estimates pending analyst review.
"""

from __future__ import annotations

from app.domains.finding.domain.enums import Severity

# (score, vector) per severity band. Vectors describe a plausible
# "typical" case for that severity - e.g. Critical assumes network
# attack vector with high impact across all three of C/I/A, which is
# representative of things like unauthenticated RCE or SQLi, but the
# real vector will vary per finding.
_SEVERITY_ESTIMATES: dict[Severity, tuple[float, str]] = {
    Severity.CRITICAL: (9.8, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    Severity.HIGH: (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"),
    Severity.MEDIUM: (5.3, "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N"),
    Severity.LOW: (3.1, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"),
    Severity.INFORMATIONAL: (0.0, "CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N"),
}


def estimate_cvss(severity: Severity) -> tuple[float, str]:
    """
    Returns (score, vector) for the given severity band. Callers should
    surface these as estimates, not authoritative scores.
    """

    return _SEVERITY_ESTIMATES[severity]
