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
    """Apply all correlation predicates to one static finding."""
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
    """Move priority up/down by delta within the fixed priority ladder."""
    idx = _PRIORITY_ORDER.index(current) if current in _PRIORITY_ORDER else 1
    idx = max(0, min(len(_PRIORITY_ORDER) - 1, idx + delta))
    return _PRIORITY_ORDER[idx]


CorrelationFn = Callable[
    [StaticFinding, RuntimeSnapshot],
    tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]],
]


def _ssh_listening_externally(runtime: RuntimeSnapshot) -> list[ListeningEndpoint]:
    """Return TCP/22 listeners that are not loopback-only binds."""
    out: list[ListeningEndpoint] = []
    for e in runtime.listening_endpoints:
        if e.protocol != "tcp" or e.local_port != 22:
            continue
        if _is_non_loopback_bind(e.local_address):
            out.append(e)
    return out


def _is_non_loopback_bind(addr: str) -> bool:
    """Treat wildcard and non-local addresses as externally reachable."""
    if addr in ("0.0.0.0", "[::]", "*", "*:*", "[::]:*"):
        return True
    if addr.startswith("127.") or addr in ("[::1]", "localhost"):
        return False
    return True


def _rule_ssh_noncompliant_plus_exposed_22(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Increase SSH finding priority when sshd appears externally exposed."""
    if static.rule_id == "UBTU-24-100800" or static.rule_id.startswith("UBTU-24-100810"):
        return None, [], []
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
    """Attach listener evidence for socket-exposure-tagged findings."""
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
    """Escalate firewall findings when many sockets are listening."""
    if static.rule_id in {"UBTU-24-100300", "UBTU-24-100310"}:
        return None, [], []
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
    """Raise SSH urgency when failed auth hints are high."""
    if static.rule_id.startswith("UBTU-24-100810"):
        return None, [], []
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
    """Raise authentication-category urgency for repeated auth failures."""
    if static.rule_id == "UBTU-24-400110":
        return None, [], []
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


def _rule_firewall_install_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100300 with firewall framework runtime availability."""
    if static.rule_id != "UBTU-24-100300":
        return None, [], []

    ufw = runtime.ufw_installed_runtime
    alt = runtime.alternative_firewall_available
    alt_name = runtime.alternative_firewall_name or "none-detected"
    ev = [
        FindingEvidence("ufw_installed_runtime", str(ufw).lower(), {}),
        FindingEvidence("alternative_firewall_available", f"{str(alt).lower()} ({alt_name})", {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if alt is True:
            note = (
                "UBTU-24-100300 reports ufw not installed, but an alternative firewall "
                f"framework appears present at runtime ({alt_name})."
            )
            return None, ev, [note]
        adj = PriorityAdjustment(
            reason=(
                "UBTU-24-100300 is non-compliant and no alternative firewall framework "
                "was detected at runtime; host may lack baseline application firewall capability."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    return None, ev, []


def _rule_firewall_activation_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100310 with ufw runtime activation/enforcement state."""
    if static.rule_id != "UBTU-24-100310":
        return None, [], []

    installed = runtime.ufw_installed_runtime
    active = runtime.ufw_active_runtime
    rules = runtime.ufw_rules_present_runtime
    kernel_loaded = runtime.kernel_packet_filter_loaded
    ev = [
        FindingEvidence("ufw_installed_runtime", str(installed).lower(), {}),
        FindingEvidence("ufw_active_runtime", str(active).lower(), {}),
        FindingEvidence("ufw_rules_present_runtime", str(rules).lower(), {}),
        FindingEvidence("kernel_packet_filter_loaded", str(kernel_loaded).lower(), {}),
    ]

    if installed is False:
        note = "UFW not detected at runtime; installation requirement is handled by UBTU-24-100300."
        return None, ev, [note]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if active is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100310 is non-compliant and ufw does not appear active at runtime; "
                    "firewall may be present but not enforcing host network policy."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if rules is False or kernel_loaded is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100310 is non-compliant and ufw enforcement signals are weak "
                    "(missing rules and/or no kernel packet filter rules detected)."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and (rules is False or kernel_loaded is False):
        adj = PriorityAdjustment(
            reason=(
                "UFW check is compliant but runtime enforcement appears incomplete "
                "(no active rules and/or kernel filter rules missing)."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and active is True and rules is True and kernel_loaded is True:
        return None, ev, ["UFW runtime signals indicate active firewall with applied rules."]

    return None, ev, []


def _rule_apparmor_install_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100500 with AppArmor runtime health signals."""
    if static.rule_id != "UBTU-24-100500":
        return None, [], []

    inst = runtime.apparmor_installed_runtime
    kern = runtime.apparmor_kernel_enabled
    loaded = runtime.apparmor_profiles_loaded
    enforced = runtime.apparmor_profiles_enforced
    ev = [
        FindingEvidence("apparmor_installed_runtime", str(inst).lower(), {}),
        FindingEvidence("apparmor_kernel_enabled", str(kern).lower(), {}),
        FindingEvidence("apparmor_profiles_loaded", str(loaded).lower(), {}),
        FindingEvidence("apparmor_profiles_enforced", str(enforced).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if inst is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100500 is non-compliant and AppArmor does not appear installed; "
                    "mandatory access control layer is likely missing."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if kern is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100500 is non-compliant and AppArmor does not appear enabled in kernel runtime state."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if loaded is False or enforced is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100500 is non-compliant and AppArmor profiles appear missing or not enforced."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and (kern is not True or loaded is False or enforced is False):
        adj = PriorityAdjustment(
            reason=(
                "AppArmor package check is compliant, but runtime indicates incomplete enablement "
                "or ineffective profile enforcement."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and kern is True and loaded is True and enforced is True:
        return None, ev, ["AppArmor runtime signals indicate enabled kernel support and enforced profiles."]

    return None, ev, []


def _rule_apparmor_service_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100510 enabled/active checks with runtime AppArmor state."""
    if not static.rule_id.startswith("UBTU-24-100510"):
        return None, [], []

    svc = runtime.apparmor_service_active
    kern = runtime.apparmor_kernel_enabled
    loaded = runtime.apparmor_profiles_loaded
    enforced = runtime.apparmor_profiles_enforced
    ev = [
        FindingEvidence("apparmor_service_active", str(svc).lower(), {}),
        FindingEvidence("apparmor_kernel_enabled", str(kern).lower(), {}),
        FindingEvidence("apparmor_profiles_loaded", str(loaded).lower(), {}),
        FindingEvidence("apparmor_profiles_enforced", str(enforced).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if svc is not True:
            adj = PriorityAdjustment(
                reason=(
                    f"{static.rule_id} is non-compliant and apparmor.service does not appear active; "
                    "AppArmor may not be operational."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if kern is not True:
            adj = PriorityAdjustment(
                reason=(
                    f"{static.rule_id} is non-compliant and AppArmor kernel enforcement is not enabled."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if loaded is False or enforced is False:
            adj = PriorityAdjustment(
                reason=(
                    f"{static.rule_id} is non-compliant and AppArmor profiles do not appear fully enforced."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and (svc is not True or kern is not True or enforced is False):
        adj = PriorityAdjustment(
            reason=(
                "AppArmor service check is compliant, but runtime indicates service/enforcement gaps "
                "that reduce effective mandatory access control."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and svc is True and kern is True and enforced is True:
        return None, ev, ["AppArmor runtime signals indicate active service with enforced profiles."]

    return None, ev, []


def _rule_pwquality_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100600 with runtime PAM pwquality usage signals."""
    if static.rule_id != "UBTU-24-100600":
        return None, [], []

    inst = runtime.pwquality_package_installed_runtime
    ref = runtime.pwquality_pam_referenced
    params = runtime.pwquality_params_defined
    flow = runtime.pwquality_password_flow_enforced
    ev = [
        FindingEvidence("pwquality_package_installed_runtime", str(inst).lower(), {}),
        FindingEvidence("pwquality_pam_referenced", str(ref).lower(), {}),
        FindingEvidence("pwquality_params_defined", str(params).lower(), {}),
        FindingEvidence("pwquality_password_flow_enforced", str(flow).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if inst is False:
            note = (
                "UBTU-24-100600 is non-compliant and libpam-pwquality does not appear installed; "
                "password quality capability is missing."
            )
            return None, ev, [note]
        if ref is not True:
            note = (
                "UBTU-24-100600 is non-compliant and pam_pwquality.so is not referenced in PAM "
                "password configuration."
            )
            return None, ev, [note]
        if params is not True:
            note = (
                "UBTU-24-100600 is non-compliant and pwquality parameters were not detected; "
                "password quality policy may be weak."
            )
            return None, ev, [note]
        if flow is not True:
            note = (
                "UBTU-24-100600 is non-compliant and password-change PAM flow does not appear to "
                "enforce pwquality."
            )
            return None, ev, [note]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and ref is True and params is True and flow is True:
        return None, ev, ["pwquality runtime signals indicate PAM integration and active policy enforcement."]

    if static.status == ComplianceStatus.COMPLIANT:
        note = (
            "UBTU-24-100600 is compliant in static checks, but runtime pwquality signals are incomplete; "
            "review PAM usage and parameter definitions."
        )
        return None, ev, [note]

    return None, ev, []


def _rule_ssh_install_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100800 with SSH runtime availability signals."""
    if static.rule_id != "UBTU-24-100800":
        return None, [], []

    svc = runtime.ssh_service_active_runtime
    proc = runtime.sshd_process_running_runtime
    p22 = runtime.ssh_port_22_listening_runtime
    ev = [
        FindingEvidence("ssh_service_active_runtime", str(svc).lower(), {}),
        FindingEvidence("sshd_process_running_runtime", str(proc).lower(), {}),
        FindingEvidence("ssh_port_22_listening_runtime", str(p22).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if svc is True or proc is True or p22 is True:
            note = (
                "UBTU-24-100800 is non-compliant, but SSH runtime signals are present "
                "(service/process/port 22). Verify package detection and SSH package variants."
            )
            return None, ev, [note]
        note = "UBTU-24-100800 is non-compliant and SSH does not appear available at runtime."
        return None, ev, [note]

    if static.status == ComplianceStatus.COMPLIANT and (svc is not True or proc is not True or p22 is not True):
        note = (
            "SSH package check is compliant, but runtime availability appears incomplete "
            "(service/process/port 22 mismatch)."
        )
        return None, ev, [note]

    if static.status == ComplianceStatus.COMPLIANT and svc is True and proc is True and p22 is True:
        return None, ev, ["SSH runtime signals indicate active service and listening TCP/22."]

    return None, ev, []


def _rule_ssh_service_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100810 enabled/active checks with SSH runtime state."""
    if not static.rule_id.startswith("UBTU-24-100810"):
        return None, [], []

    active = runtime.ssh_service_active_runtime
    enabled = runtime.ssh_service_enabled_runtime
    p22 = runtime.ssh_port_22_listening_runtime
    ev = [
        FindingEvidence("ssh_service_active_runtime", str(active).lower(), {}),
        FindingEvidence("ssh_service_enabled_runtime", str(enabled).lower(), {}),
        FindingEvidence("ssh_port_22_listening_runtime", str(p22).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if active is not True and enabled is not True:
            adj = PriorityAdjustment(
                reason=(
                    f"{static.rule_id} is non-compliant and SSH is neither active nor enabled; "
                    "service is unavailable now and unlikely to start after reboot."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if static.rule_id.endswith("-active") and enabled is True and active is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100810-active is non-compliant: SSH is enabled but currently down."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if static.rule_id.endswith("-enabled") and active is True and enabled is not True:
            note = (
                "UBTU-24-100810-enabled is non-compliant: SSH is active now but not enabled for reboot persistence."
            )
            return None, ev, [note]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and active is True and enabled is True and p22 is False:
        adj = PriorityAdjustment(
            reason=(
                f"{static.rule_id} is compliant, but SSH is not listening on TCP/22; "
                "runtime indicates possible misconfiguration or accessibility issue."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and active is True and enabled is True and p22 is True:
        return None, ev, ["SSH runtime signals indicate active service, boot enablement, and listening TCP/22."]

    return None, ev, []


def _rule_boot_auth_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-102000 with runtime boot/auth enforcement signals."""
    if static.rule_id != "UBTU-24-102000":
        return None, [], []

    auth = runtime.grub_auth_configured_runtime
    protected = runtime.grub_cfg_protected_runtime
    single = runtime.single_user_auth_required_runtime
    ev = [
        FindingEvidence("grub_auth_configured_runtime", str(auth).lower(), {}),
        FindingEvidence("grub_cfg_protected_runtime", str(protected).lower(), {}),
        FindingEvidence("single_user_auth_required_runtime", str(single).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if auth is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-102000 is non-compliant and GRUB authentication directives are not "
                    "detected in effective boot configuration."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if protected is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-102000 is non-compliant and grub.cfg does not appear strongly protected, "
                    "so boot auth settings may be modifiable."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if single is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-102000 is non-compliant and rescue/emergency auth enforcement appears weak "
                    "(sulogin not detected)."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and (auth is not True or protected is not True or single is False):
        adj = PriorityAdjustment(
            reason=(
                "Boot auth check is compliant, but runtime boot-protection signals are incomplete "
                "(auth directives, file protection, or single-user auth)."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and auth is True and protected is True and single is not False:
        return None, ev, ["Boot authentication runtime signals indicate configured and protected enforcement."]

    return None, ev, []


def _rule_root_login_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-400110 with root-account and SSH root-login runtime state."""
    if static.rule_id != "UBTU-24-400110":
        return None, [], []

    locked = runtime.root_account_locked_runtime
    ssh_root_allowed = runtime.ssh_permit_root_login_allowed_runtime
    root_sessions = runtime.active_root_sessions_runtime
    ev = [
        FindingEvidence("root_account_locked_runtime", str(locked).lower(), {}),
        FindingEvidence("ssh_permit_root_login_allowed_runtime", str(ssh_root_allowed).lower(), {}),
        FindingEvidence("active_root_sessions_runtime", str(root_sessions).lower(), {}),
    ]
    notes: list[str] = []

    if root_sessions is True:
        notes.append("Active root sessions detected at runtime; verify this is expected administrative activity.")

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if locked is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-400110 is non-compliant and root account appears unlocked; "
                    "direct privileged login may be possible."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason, *notes]
        if ssh_root_allowed is True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-400110 is non-compliant and sshd appears to allow direct root login."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason, *notes]
        return None, ev, notes

    if static.status == ComplianceStatus.COMPLIANT and locked is True and ssh_root_allowed is False:
        return None, ev, [*notes, "Runtime signals indicate direct root login is prevented."]

    return None, ev, notes


def _rule_pending_updates_high_exposure(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Escalate update findings when pending patches and exposure coexist."""
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


def _rule_timesyncd_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100010 with timesyncd runtime state."""
    if static.rule_id != "UBTU-24-100010":
        return None, [], []

    svc = runtime.timesyncd_service_active
    proc = runtime.timesyncd_process_running
    alt = runtime.approved_timesync_service_active
    ev = [
        FindingEvidence("timesyncd_service_active", str(svc).lower(), {}),
        FindingEvidence("timesyncd_process_running", str(proc).lower(), {}),
        FindingEvidence(
            "approved_timesync_service_active",
            f"{str(alt).lower()} ({runtime.approved_timesync_service_name or 'none-detected'})",
            {},
        ),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if svc is True or proc is True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100010 is non-compliant and systemd-timesyncd appears active "
                    "at runtime; prohibited component is likely in operational use."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        note = (
            "UBTU-24-100010 is non-compliant but systemd-timesyncd does not appear active "
            "in current runtime checks."
        )
        return None, ev, [note]

    if static.status == ComplianceStatus.COMPLIANT and alt is False:
        note = (
            "Time-sync package check is compliant, but no approved alternative time "
            "synchronization service appears active at runtime."
        )
        return None, ev, [note]

    return None, ev, []


def _rule_ntp_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100020 with ntp runtime state."""
    if static.rule_id != "UBTU-24-100020":
        return None, [], []

    svc = runtime.ntp_service_active
    proc = runtime.ntp_process_running
    alt = runtime.approved_timesync_service_active
    ev = [
        FindingEvidence("ntp_service_active", str(svc).lower(), {}),
        FindingEvidence("ntp_process_running", str(proc).lower(), {}),
        FindingEvidence(
            "approved_timesync_service_active",
            f"{str(alt).lower()} ({runtime.approved_timesync_service_name or 'none-detected'})",
            {},
        ),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if svc is True or proc is True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100020 is non-compliant and ntp/ntpd appears active at runtime; "
                    "prohibited component is likely in operational use."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        note = (
            "UBTU-24-100020 is non-compliant but ntp/ntpd does not appear active "
            "in current runtime checks."
        )
        return None, ev, [note]

    if static.status == ComplianceStatus.COMPLIANT and alt is False:
        note = (
            "NTP package check is compliant, but no approved alternative time "
            "synchronization service appears active at runtime."
        )
        return None, ev, [note]

    return None, ev, []


def _rule_telnet_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100030 with telnet runtime/exposure state."""
    if static.rule_id != "UBTU-24-100030":
        return None, [], []

    svc = runtime.telnet_service_active
    proc = runtime.telnetd_process_running
    p23 = runtime.telnet_port_23_listening
    ev = [
        FindingEvidence("telnet_service_active", str(svc).lower(), {}),
        FindingEvidence("telnetd_process_running", str(proc).lower(), {}),
        FindingEvidence("telnet_port_23_listening", str(p23).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if svc is True or proc is True or p23 is True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100030 is non-compliant and telnet runtime signals are present "
                    "(service/process/listening TCP/23); insecure remote access may be exposed."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        note = "UBTU-24-100030 is non-compliant but telnet does not appear active in runtime checks."
        return None, ev, [note]

    if static.status == ComplianceStatus.COMPLIANT and p23 is True:
        adj = PriorityAdjustment(
            reason=(
                "Telnet package check is compliant, but TCP/23 is listening at runtime; "
                "this may indicate alternative telnet exposure or misconfiguration."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    return None, ev, []


def _rule_rsyslog_runtime_context(
    static: StaticFinding,
    runtime: RuntimeSnapshot,
) -> tuple[PriorityAdjustment | None, list[FindingEvidence], list[str]]:
    """Correlate CIS UBTU-24-100200 parts with runtime logging health signals."""
    if not static.rule_id.startswith("UBTU-24-100200"):
        return None, [], []

    svc = runtime.rsyslog_service_active
    proc = runtime.rsyslogd_process_running
    writes = runtime.syslog_recently_updated
    ev = [
        FindingEvidence("rsyslog_service_active", str(svc).lower(), {}),
        FindingEvidence("rsyslogd_process_running", str(proc).lower(), {}),
        FindingEvidence("syslog_recently_updated", str(writes).lower(), {}),
    ]

    if static.status == ComplianceStatus.NON_COMPLIANT:
        if static.rule_id.endswith("-install"):
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100200 install check is non-compliant; rsyslog package appears missing, "
                    "which can break baseline event logging capability."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if svc is not True or proc is not True:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100200 service check is non-compliant and rsyslog does not appear fully active "
                    "(service/process); logging service may not function reliably."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        if writes is False:
            adj = PriorityAdjustment(
                reason=(
                    "UBTU-24-100200 is non-compliant and /var/log/syslog does not appear recently updated; "
                    "logging output may be misconfigured or failing."
                ),
                delta=1,
                supporting_evidence=tuple(ev),
            )
            return adj, ev, [adj.reason]
        return None, ev, []

    if static.status == ComplianceStatus.COMPLIANT and svc is True and writes is False:
        adj = PriorityAdjustment(
            reason=(
                "Rsyslog checks are compliant but /var/log/syslog does not appear recently updated; "
                "runtime behavior suggests potential logging pipeline issues."
            ),
            delta=1,
            supporting_evidence=tuple(ev),
        )
        return adj, ev, [adj.reason]

    if static.status == ComplianceStatus.COMPLIANT and svc is True and writes is True:
        return None, ev, ["Rsyslog runtime signals indicate active service and ongoing log writes."]

    return None, ev, []


_CORRELATION_RULES: list[CorrelationFn] = [
    _rule_timesyncd_runtime_context,
    _rule_ntp_runtime_context,
    _rule_telnet_runtime_context,
    _rule_rsyslog_runtime_context,
    _rule_firewall_install_runtime_context,
    _rule_firewall_activation_runtime_context,
    _rule_apparmor_install_runtime_context,
    _rule_apparmor_service_runtime_context,
    _rule_pwquality_runtime_context,
    _rule_ssh_install_runtime_context,
    _rule_ssh_service_runtime_context,
    _rule_boot_auth_runtime_context,
    _rule_root_login_runtime_context,
    _rule_socket_exposure,
    _rule_ssh_noncompliant_plus_exposed_22,
    _rule_firewall_noncompliant_many_listeners,
    _rule_failed_auth_ssh_context,
    _rule_failed_auth_authentication_category,
    _rule_pending_updates_high_exposure,
]
