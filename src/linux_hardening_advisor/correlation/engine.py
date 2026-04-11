"""
Rule-based correlation: priority is adjusted using explicit, readable logic.

"""

from __future__ import annotations

from typing import Callable, Sequence

from linux_hardening_advisor.models.findings import (
    ComplianceStatus,
    CorrelatedFinding,
    FindingEvidence,
    PriorityAdjustment,
    StaticFinding,
)
from linux_hardening_advisor.models.runtime_state import ListeningEndpoint, RuntimeSnapshot

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


def _ssh_listening_externally(runtime: RuntimeSnapshot) -> list[ListeningEndpoint]:
    out: list[ListeningEndpoint] = []
    for e in runtime.listening_endpoints:
        if e.protocol != "tcp" or e.local_port != 22:
            continue
        if _is_non_loopback_bind(e.local_address):
            out.append(e)
    return out


def _is_non_loopback_bind(addr: str) -> bool:
    if addr in ("0.0.0.0", "[::]", "*", "*:*", "[::]:*"):
        return True
    if addr.startswith("127.") or addr in ("[::1]", "localhost"):
        return False
    return True


def _rule_ssh_noncompliant_plus_exposed_22(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []
    if "ssh" not in static.tags and static.category != "ssh":
        return None, [], []
    exposed = _ssh_listening_externally(runtime)
    if not exposed:
        return None, [], []
    detail = ", ".join(f"{e.local_address}:{e.local_port}" for e in exposed[:6])
    ev = FindingEvidence(
        "ssh_listen",
        f"TCP/22 on non-loopback: {detail}",
        {"endpoints": len(exposed)},
    )
    adj = PriorityAdjustment(
        reason=(
            "SSH-related control is non-compliant and sshd appears to listen on "
            "non-loopback addresses; exposure may be reachable from the network."
        ),
        delta=1,
        supporting_evidence=(ev,),
    )
    return adj, [ev], [adj.reason]


def _rule_socket_exposure(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
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


def _rule_firewall_noncompliant_many_listeners(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    if static.category != "firewall":
        return None, [], []
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []
    n = len(runtime.listening_endpoints)
    if n < 5:
        return None, [], []
    ev = FindingEvidence("listening_sockets", f"count={n}", {})
    adj = PriorityAdjustment(
        reason=(
            "Firewall-related finding is non-compliant and the host reports several "
            "listening sockets; network exposure may be elevated."
        ),
        delta=1,
        supporting_evidence=(ev,),
    )
    return adj, [ev], [adj.reason]


def _rule_failed_auth_ssh_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []
    if "ssh" not in static.tags and static.category != "ssh":
        return None, [], []
    c = runtime.failed_login_hint_count
    if c < 8:
        return None, [], []
    ev = FindingEvidence(
        "auth_journal",
        f"heuristic_failed_login_hints={c}",
        {},
    )
    adj = PriorityAdjustment(
        reason=(
            "Recent authentication log excerpt shows repeated failure patterns; "
            "SSH hardening findings may be more urgent while brute-force noise is present."
        ),
        delta=1,
        supporting_evidence=(ev,),
    )
    return adj, [ev], [adj.reason]


def _rule_failed_auth_authentication_category(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    if static.category != "authentication":
        return None, [], []
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []
    c = runtime.failed_login_hint_count
    if c < 5:
        return None, [], []
    ev = FindingEvidence("auth_journal", f"heuristic_failed_login_hints={c}", {})
    adj = PriorityAdjustment(
        reason=(
            "Authentication-related control is non-compliant and recent logs suggest "
            "elevated failed-login activity; review account lockout and PAM settings."
        ),
        delta=1,
        supporting_evidence=(ev,),
    )
    return adj, [ev], [adj.reason]


def _rule_pending_updates_high_exposure(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    if static.category != "updates":
        return None, [], []
    if static.status != ComplianceStatus.NON_COMPLIANT:
        return None, [], []
    n_listen = len(runtime.listening_endpoints)
    pending = runtime.pending_apt_upgrades
    if pending is None or pending < 1 or n_listen < 4:
        return None, [], []
    ev = FindingEvidence(
        "updates_and_exposure",
        f"pending_apt_upgrades={pending}, listening_sockets={n_listen}",
        {},
    )
    adj = PriorityAdjustment(
        reason=(
            "Pending package upgrades coexist with multiple listening services; "
            "patching may reduce remotely exploitable surface."
        ),
        delta=1,
        supporting_evidence=(ev,),
    )
    return adj, [ev], [adj.reason]


_CORRELATION_RULES: list[CorrelationFn] = [
    _rule_socket_exposure,
    _rule_ssh_noncompliant_plus_exposed_22,
    _rule_firewall_noncompliant_many_listeners,
    _rule_failed_auth_ssh_context,
    _rule_failed_auth_authentication_category,
    _rule_pending_updates_high_exposure,
]
