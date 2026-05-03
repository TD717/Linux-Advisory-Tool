"""Evaluate a ``BenchmarkRule`` against the local host (static checks)."""

from __future__ import annotations

import logging
import stat
from pathlib import Path

from linux_hardening_advisor.collectors.subprocess_runner import (
    CommandResult,
    format_command_for_evidence,
    run_argv,
    run_shell,
)
from linux_hardening_advisor.models.findings import ComplianceStatus, FindingEvidence, StaticFinding
from linux_hardening_advisor.models.rules import BenchmarkRule, CheckType, FindingCondition

logger = logging.getLogger(__name__)


def evaluate_rule(rule: BenchmarkRule) -> StaticFinding:
    """Dispatch on ``rule.check_type`` and return a normalized ``StaticFinding``."""
    try:
        pred_non_compliant, evidence = _evaluate_predicate(rule)
    except Exception as exc:
        logger.exception("Rule %s failed: %s", rule.id, exc)
        return _error_finding(rule, str(exc))

    non_compliant = _apply_finding_condition(pred_non_compliant, rule.finding_condition)
    status = ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT
    return _build_finding(rule, status, evidence, None)


def _apply_finding_condition(pred: bool, fc: FindingCondition) -> bool:
    """Interpret the predicate according to the rule finding condition."""
    if fc == FindingCondition.NON_COMPLIANT_IF_TRUE:
        return pred
    if fc == FindingCondition.NON_COMPLIANT_IF_FALSE:
        return not pred
    raise ValueError(f"Unknown finding condition: {fc}")


def _error_finding(rule: BenchmarkRule, err: str) -> StaticFinding:
    """Build a standardized ERROR finding when evaluation fails."""
    return StaticFinding(
        rule_id=rule.id,
        section=rule.section,
        title=rule.title,
        category=rule.category,
        rationale=rule.rationale,
        recommendation=rule.recommendation,
        severity=rule.severity,
        tags=rule.tags,
        status=ComplianceStatus.ERROR,
        expected_compliant_state=_expected_summary(rule),
        verification_summary="Evaluation error",
        evidence=(FindingEvidence("error", err),),
        raw_error=err,
    )


def _build_finding(
    rule: BenchmarkRule,
    status: ComplianceStatus,
    evidence: tuple[FindingEvidence, ...],
    raw_error: str | None,
) -> StaticFinding:
    """Construct a normalized StaticFinding from evaluated fields."""
    return StaticFinding(
        rule_id=rule.id,
        section=rule.section,
        title=rule.title,
        category=rule.category,
        rationale=rule.rationale,
        recommendation=rule.recommendation,
        severity=rule.severity,
        tags=rule.tags,
        status=status,
        expected_compliant_state=_expected_summary(rule),
        verification_summary=_verification_summary(rule, evidence),
        evidence=evidence,
        raw_error=raw_error,
    )


def _expected_summary(rule: BenchmarkRule) -> str:
    """Create a compact expected-state summary for report rendering."""
    return str(rule.expected) if rule.expected else "(see rule documentation)"


def _verification_summary(rule: BenchmarkRule, evidence: tuple[FindingEvidence, ...]) -> str:
    """Prefer command evidence text, fallback to check type summary."""
    for ev in evidence:
        if ev.label == "command":
            return ev.detail[:500]
    return f"check_type={rule.check_type.value}"


def _evaluate_predicate(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Return (predicate_for_non_compliant_if_true_path, evidence)."""
    ct = rule.check_type
    if ct == CheckType.COMMAND_OUTPUT_CONTAINS:
        return _cmd_output_contains(rule, want_contains=True)
    if ct == CheckType.COMMAND_OUTPUT_NOT_CONTAINS:
        return _cmd_output_contains(rule, want_contains=False)
    if ct == CheckType.COMMAND_EXIT_STATUS:
        return _command_exit_status(rule)
    if ct == CheckType.FILE_EXISTS:
        return _file_exists(rule, want=True)
    if ct == CheckType.FILE_NOT_EXISTS:
        return _file_exists(rule, want=False)
    if ct == CheckType.FILE_MODE:
        return _file_mode(rule)
    if ct == CheckType.PACKAGE_ABSENT:
        return _package_absent_debian(rule)
    if ct == CheckType.PACKAGE_PRESENT:
        return _package_present_debian(rule)
    if ct == CheckType.SERVICE_DISABLED:
        return _service_disabled(rule)
    if ct == CheckType.SERVICE_ENABLED:
        return _service_enabled(rule)
    if ct == CheckType.SERVICE_ACTIVE:
        return _service_active(rule, want=True)
    if ct == CheckType.SERVICE_INACTIVE:
        return _service_active(rule, want=False)
    if ct == CheckType.CONFIG_VALUE_EQUALS:
        return _config_value_equals(rule, want=True)
    if ct == CheckType.CONFIG_VALUE_NOT_EQUALS:
        return _config_value_equals(rule, want=False)
    if ct == CheckType.CUSTOM:
        return _custom_not_implemented(rule)
    raise ValueError(f"Unsupported check_type: {ct}")


def _cmd_output_contains(rule: BenchmarkRule, *, want_contains: bool) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate whether command output should contain or exclude a substring."""
    cmd = rule.verification_command or rule.target.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("command_output_* requires verification_command or target.command")
    substring = str(rule.expected.get("substring", ""))
    result = run_shell(cmd.strip())
    combined = (result.stdout or "") + (result.stderr or "")
    contains = substring in combined
    pred = contains if want_contains else not contains
    ev = (
        FindingEvidence(
            "command",
            format_command_for_evidence(result),
            {"stdout": result.stdout, "stderr": result.stderr, "returncode": result.returncode},
        ),
    )
    return pred, ev


def _command_exit_status(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate command return code against the expected exit status."""
    cmd = rule.verification_command or rule.target.get("command")
    if not isinstance(cmd, str) or not cmd.strip():
        raise ValueError("command_exit_status requires verification_command or target.command")
    expected = int(rule.expected.get("exit_code", 0))
    result = run_shell(cmd.strip())
    pred = result.returncode != expected
    ev = (
        FindingEvidence(
            "command",
            format_command_for_evidence(result),
            {"returncode": result.returncode, "expected": expected},
        ),
    )
    return pred, ev


def _file_exists(rule: BenchmarkRule, *, want: bool) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate file presence/absence controls and attach path evidence."""
    path = Path(str(rule.target.get("path", ""))).expanduser()
    exists = path.exists()
    # predicate: "non-compliant signal" before finding_condition — here pred means
    # "file exists" as a raw fact for FILE_EXISTS; we map below in caller via types.
    if want:
        pred = not exists  # missing file => non-compliant when NON_COMPLIANT_IF_TRUE
        ev = (FindingEvidence("path", str(path), {"exists": exists}),)
        return pred, ev
    pred = exists  # file should not exist but does
    ev = (FindingEvidence("path", str(path), {"exists": exists}),)
    return pred, ev


def _file_mode(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate a file permission mode check using octal expectation."""
    path = Path(str(rule.target.get("path", ""))).expanduser()
    if not path.exists():
        return True, (FindingEvidence("path", str(path), {"exists": False}),)
    mode_oct = rule.expected.get("mode_octal")
    if mode_oct is None:
        raise ValueError("file_mode requires expected.mode_octal (e.g. 600)")
    want = int(str(mode_oct), 8)
    st = path.stat()
    actual = stat.S_IMODE(st.st_mode)
    pred = actual != want
    ev = (FindingEvidence("file_mode", str(path), {"actual_octal": oct(actual), "expected_octal": oct(want)}),)
    return pred, ev


def _dpkg_installed(package: str) -> bool:
    """Return True when dpkg reports the package as installed."""
    r = run_argv(["dpkg-query", "-W", "-f=${Status}", package])
    out = (r.stdout or "").strip()
    if r.returncode != 0 and not out:
        return False
    return "install ok installed" in out


def _package_absent_debian(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate Debian package-absent rule via dpkg-query state."""
    pkg = str(rule.target.get("package", ""))
    if not pkg:
        raise ValueError("package_absent requires target.package")
    installed = _dpkg_installed(pkg)
    ev = (FindingEvidence("dpkg", f"package={pkg}", {"installed": installed}),)
    return installed, ev


def _package_present_debian(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate Debian package-present rule via dpkg-query state."""
    pkg = str(rule.target.get("package", ""))
    if not pkg:
        raise ValueError("package_present requires target.package")
    installed = _dpkg_installed(pkg)
    ev = (FindingEvidence("dpkg", f"package={pkg}", {"installed": installed}),)
    return not installed, ev


def _systemctl_is_enabled(service: str) -> str | None:
    """Return systemctl is-enabled state or None on lookup failure."""
    r = run_argv(["systemctl", "is-enabled", service], timeout_s=30.0)
    out = (r.stdout or "").strip()
    if r.returncode == 0 and out:
        return out
    return None


def _service_disabled(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate service-disabled control using systemd enabled-state output."""
    svc = str(rule.target.get("service", ""))
    if not svc:
        raise ValueError("service_disabled requires target.service")
    state = _systemctl_is_enabled(svc)
    if state is None:
        # Not installed or not a unit — treat as disabled for advisory purposes
        ev = (FindingEvidence("systemctl", f"is-enabled {svc}", {"state": "unknown_or_inactive"}),)
        return False, ev
    bad = state not in ("disabled", "masked", "inactive")
    ev = (FindingEvidence("systemctl", f"is-enabled {svc}", {"state": state}),)
    return bad, ev


def _service_enabled(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate service-enabled control using systemd enabled-state output."""
    svc = str(rule.target.get("service", ""))
    if not svc:
        raise ValueError("service_enabled requires target.service")
    state = _systemctl_is_enabled(svc)
    bad = state not in ("enabled", "static", "enabled-runtime")
    ev = (FindingEvidence("systemctl", f"is-enabled {svc}", {"state": state}),)
    return bad, ev


def _service_active(rule: BenchmarkRule, *, want: bool) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate service active/inactive state using systemctl is-active."""
    svc = str(rule.target.get("service", ""))
    if not svc:
        raise ValueError("service_active/inactive requires target.service")
    r = run_argv(["systemctl", "is-active", svc], timeout_s=30.0)
    active = (r.stdout or "").strip() == "active"
    if want:
        pred = not active
    else:
        pred = active
    ev = (FindingEvidence("systemctl", f"is-active {svc}", {"active": active, "stdout": r.stdout.strip()}),)
    return pred, ev


def _config_value_equals(rule: BenchmarkRule, *, want: bool) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Evaluate key/value config controls in a simple line-based parser."""
    path = Path(str(rule.target.get("path", ""))).expanduser()
    key = str(rule.target.get("key", ""))
    expected_val = str(rule.expected.get("value", ""))
    if not path or not key:
        raise ValueError("config_value_* requires target.path and target.key")
    if not path.is_file():
        return True, (FindingEvidence("config", str(path), {"error": "missing_file"}),)
    text = path.read_text(encoding="utf-8", errors="replace")
    actual = _parse_simple_config(text, key)
    matches = actual is not None and actual.strip() == expected_val.strip()
    pred = not matches if want else matches
    ev = (
        FindingEvidence(
            "config",
            f"{path} {key}",
            {"actual": actual, "expected": expected_val},
        ),
    )
    return pred, ev


def _parse_simple_config(text: str, key: str) -> str | None:
    """Support ``KEY=value`` and ``KEY value`` (first match)."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
        parts = line.split(None, 1)
        if len(parts) == 2 and parts[0] == key:
            return parts[1].strip().strip('"').strip("'")
    return None


def _custom_not_implemented(rule: BenchmarkRule) -> tuple[bool, tuple[FindingEvidence, ...]]:
    """Signal that custom check types need project-specific handlers."""
    raise NotImplementedError(
        "check_type=custom requires a registered handler (extend static/evaluator.py or use a plugin entry point)."
    )
