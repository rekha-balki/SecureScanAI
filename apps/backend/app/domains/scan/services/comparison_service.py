"""
Scan-to-scan comparison (BRD "historical comparisons" / FRS Part 5
Section 108 progress tracking taken further: what changed between two
scans of the same target).

Findings are matched by (plugin_id, category, affected_url) rather than
their full fingerprint, since the fingerprint also includes evidence
text that can shift slightly between runs (e.g. a certificate's "days
until expiry" or a timestamp) without the underlying issue actually
being different.
"""

from __future__ import annotations

from app.domains.finding.domain.aggregates.finding import Finding


def _comparison_key(finding: Finding) -> tuple[str, str, str]:
    return (finding.plugin_id, finding.category, finding.affected_url)


def compare_findings(
    baseline: list[Finding], current: list[Finding]
) -> dict[str, list[Finding]]:
    """
    `baseline` is the earlier scan, `current` is the later one.

    Returns:
        new: present in current, not in baseline
        fixed: present in baseline, not in current
        persistent: present in both
    """

    baseline_keys = {_comparison_key(f): f for f in baseline}
    current_keys = {_comparison_key(f): f for f in current}

    new = [f for key, f in current_keys.items() if key not in baseline_keys]
    fixed = [f for key, f in baseline_keys.items() if key not in current_keys]
    persistent = [f for key, f in current_keys.items() if key in baseline_keys]

    return {"new": new, "fixed": fixed, "persistent": persistent}
