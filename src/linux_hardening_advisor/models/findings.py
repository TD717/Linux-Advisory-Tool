"""Normalized finding and report objects (thesis-friendly, explainable)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping, Sequence


class ComplianceStatus(str, Enum):
    """High-level compliance outcome for a static check."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


@dataclass(frozen=True)
class FindingEvidence:
    """Evidence attached to a finding (static command output, paths, runtime snippets)."""

    label: str
    detail: str
    data: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class StaticFinding:
    """Result of evaluating one benchmark-style static rule on the host."""

    rule_id: str
    section: str
    title: str
    category: str
    rationale: str
    recommendation: str
    severity: str
    tags: tuple[str, ...]
    status: ComplianceStatus
    expected_compliant_state: str
    verification_summary: str
    evidence: tuple[FindingEvidence, ...]
    raw_error: str | None = None


@dataclass(frozen=True)
class PriorityAdjustment:
    """Explicit, human-readable reason a priority changed after correlation."""

    reason: str
    delta: int
    supporting_evidence: tuple[FindingEvidence, ...] = ()


@dataclass(frozen=True)
class CorrelatedFinding:
    """Static finding plus runtime context and explainable priority adjustments."""

    static: StaticFinding
    runtime_evidence: tuple[FindingEvidence, ...]
    priority: str
    priority_adjustments: tuple[PriorityAdjustment, ...]
    correlation_notes: tuple[str, ...]


@dataclass
class ScanReport:
    """Full advisory output for one scan run."""

    generated_at: datetime
    hostname: str
    static_findings: Sequence[StaticFinding]
    correlated_findings: Sequence[CorrelatedFinding]
    runtime_snapshot_summary: Mapping[str, Any]

    def __post_init__(self) -> None:
        if self.generated_at.tzinfo is None:
            self.generated_at = self.generated_at.replace(tzinfo=timezone.utc)
