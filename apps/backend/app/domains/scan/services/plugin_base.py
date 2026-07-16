"""
Vulnerability Plugin Framework core types.

Implements the plugin contract described in
"SecureScan AI - Vulnerability Plugin Framework" (FRS Part 3).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

import httpx

from app.domains.finding.domain.enums import Confidence, Severity


@dataclass(slots=True)
class PluginContext:
    """
    Common context passed to every plugin (FRS Section 54).
    """

    url: str
    response: httpx.Response
    response_time_ms: float
    is_https: bool


@dataclass(slots=True)
class PluginFinding:
    """
    A single finding produced by a plugin (FRS Section 56).
    """

    category: str
    severity: Severity
    confidence: Confidence
    description: str
    evidence: str
    recommendation: str
    business_impact: str | None = None
    technical_impact: str | None = None
    owasp_reference: str | None = None
    cwe_reference: str | None = None
    references: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PluginMetadata:
    """
    Plugin metadata (FRS Section 50).
    """

    plugin_id: str
    name: str
    version: str
    category: str
    description: str
    execution_priority: int = 100


class VulnerabilityPlugin(Protocol):
    """
    Contract every plugin must satisfy.
    """

    metadata: PluginMetadata

    def evaluate(self, context: PluginContext) -> list[PluginFinding]:
        ...
