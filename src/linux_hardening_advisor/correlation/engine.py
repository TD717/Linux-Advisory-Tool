""" Rule-based correlation: priority is adjusted using explicit, readable logic. """

from __future__ import annotations

from typing import Callable, Sequence

from linux_hardening_advisor.models.findings import (
    ComplianceStatus,
    CorrelatedFinding,
    FindingEvidence,
    PriorityAdjustment,
    StaticFinding,
)
from linux_hardening_advisor.models.runtime_state import RuntimeSnapshot

# Priority labels
_PRIORITY_ORDER = ("low", "medium", "high", "critical")


def correlate_all(
    findings: Sequence[StaticFinding],
    runtime: RuntimeSnapshot,
) -> list[CorrelatedFinding]:
    """Apply all correlation rules to each static finding."""
    out: list[CorrelatedFinding] = []
    for sf in findings:
        out.append(_correlate_one(sf, runtime))
    return out


def _correlate_one(static: StaticFinding, runtime: RuntimeSnapshot) -> CorrelatedFinding:
    adjustments: list[PriorityAdjustment] = []
    notes: list[str] = []
    runtime_evidence: list[FindingEvidence] = []

    base = static.severity.lower() if static.severity else "medium"
    priority = base if base in _PRIORITY_ORDER else "medium"

    for rule in _CORRELATION_RULES:
        adj, ev, n = rule(static, runtime)
        if adj is not None:
            adjustments.append(adj)
        runtime_evidence.extend(ev)
        notes.extend(n)
        if adj is not None:
            priority = _bump_priority(priority, adj.delta)

    # Deduplicate evidence by label+detail
    seen: set[tuple[str, str]] = set()
    deduped: list[FindingEvidence] = []
    for e in runtime_evidence:
        k = (e.label, e.detail)
        if k not in seen:
            seen.add(k)
            deduped.append(e)

    return CorrelatedFinding(
        static=static,
        runtime_evidence=tuple(deduped),
        priority=priority,
        priority_adjustments=tuple(adjustments),
        correlation_notes=tuple(notes),
    )


def _bump_priority(current: str, delta: int) -> str:
    idx = _PRIORITY_ORDER.index(current) if current in _PRIORITY_ORDER else 1
    idx = max(0, min(len(_PRIORITY_ORDER) - 1, idx + delta))
    return _PRIORITY_ORDER[idx]


CorrelationFn = Callable[
    [StaticFinding, RuntimeSnapshot],
    tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]],
]


def _rule_socket_exposure(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """
    Example correlation (documented for the thesis):

    If a finding is tagged ``socket-exposure`` and is **non-compliant**, increase
    urgency when the host has several listening sockets (broader attack surface).
    """
    if "socket-exposure" not in static.tags:
        return None, [], []
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []

    n = len(runtime.listening_endpoints)
    ev = FindingEvidence(
        "listening_sockets",
        f"count={n}",
        {"endpoints": [e.local_address for e in runtime.listening_endpoints[:20]]},
    )
    if n >= 3:
        adj = PriorityAdjustment(
            reason=(
                "Runtime shows multiple listening sockets; non-compliance may increase "
                "exposure on this host."
            ),
            delta=1,
            supporting_evidence=(ev,),
        )
        return adj, [ev], [adj.reason]
    return None, [ev], []


_CORRELATION_RULES: list[CorrelationFn] = [
    _rule_socket_exposure,
]
