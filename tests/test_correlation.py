"""Correlation engine tests."""

from linux_hardening_advisor.correlation.engine import correlate_all
from linux_hardening_advisor.models.findings import ComplianceStatus, FindingEvidence, StaticFinding
from linux_hardening_advisor.models.runtime_state import ListeningEndpoint, RuntimeSnapshot


def _static(tagged: bool, non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="R1",
        section="s",
        title="t",
        category="c",
        rationale="r",
        recommendation="rec",
        severity="medium",
        tags=("socket-exposure",) if tagged else (),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def test_socket_exposure_bumps_priority():
    rt = RuntimeSnapshot(hostname="h")
    for i in range(5):
        rt.listening_endpoints.append(
            ListeningEndpoint("tcp", "0.0.0.0", 80 + i, "proc"),
        )
    sf = _static(tagged=True, non_compliant=True)
    out = correlate_all([sf], rt)
    assert len(out) == 1
    cf = out[0]
    assert cf.priority == "high"
    assert cf.priority_adjustments


def test_ssh_noncompliant_and_listening_on_22_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.listening_endpoints.append(ListeningEndpoint("tcp", "0.0.0.0", 22, "sshd"))
    sf = StaticFinding(
        rule_id="SSH-1",
        section="s",
        title="t",
        category="ssh",
        rationale="r",
        recommendation="rec",
        severity="medium",
        tags=("ssh", "cis"),
        status=ComplianceStatus.NON_COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )
    out = correlate_all([sf], rt)
    assert out[0].priority == "high"
    assert out[0].priority_adjustments


def test_firewall_noncompliant_many_listeners_bumps():
    rt = RuntimeSnapshot(hostname="h")
    for i in range(6):
        rt.listening_endpoints.append(ListeningEndpoint("tcp", "127.0.0.1", 8000 + i, None))
    sf = StaticFinding(
        rule_id="FW-1",
        section="s",
        title="t",
        category="firewall",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis",),
        status=ComplianceStatus.NON_COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )
    out = correlate_all([sf], rt)
    assert out[0].priority == "critical"


def test_no_bump_when_compliant():
    rt = RuntimeSnapshot(hostname="h")
    rt.listening_endpoints.extend(
        [
            ListeningEndpoint("tcp", "0.0.0.0", 22, None),
        ]
        * 5
    )
    sf = _static(tagged=True, non_compliant=False)
    out = correlate_all([sf], rt)
    assert out[0].priority == "medium"
    assert not out[0].priority_adjustments
