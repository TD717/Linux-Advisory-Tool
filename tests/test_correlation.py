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


def _timesync_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100010",
        section="1.2",
        title="Timesyncd package policy",
        category="time_synchronization",
        rationale="r",
        recommendation="rec",
        severity="medium",
        tags=("cis", "ubuntu-24", "time"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _ntp_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100020",
        section="1.3",
        title="NTP package policy",
        category="time_synchronization",
        rationale="r",
        recommendation="rec",
        severity="medium",
        tags=("cis", "ubuntu-24", "time"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _telnet_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100030",
        section="1.4",
        title="Telnet package policy",
        category="network_services",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "telnet"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _rsyslog_static(rule_id: str, non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id=rule_id,
        section="1.10",
        title="Rsyslog policy",
        category="logging",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "rsyslog"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _firewall_install_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100300",
        section="1.11",
        title="Firewall install policy",
        category="firewall",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "ufw", "firewall"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _firewall_active_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100310",
        section="1.12",
        title="Firewall active policy",
        category="firewall",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "ufw", "firewall"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _apparmor_install_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100500",
        section="1.15",
        title="AppArmor install policy",
        category="apparmor",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "apparmor"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _apparmor_service_static(rule_id: str, non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id=rule_id,
        section="1.16",
        title="AppArmor service policy",
        category="apparmor",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "apparmor"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _pwquality_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100600",
        section="1.18",
        title="PAM pwquality policy",
        category="authentication",
        rationale="r",
        recommendation="rec",
        severity="medium",
        tags=("cis", "ubuntu-24", "pam"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _ssh_install_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-100800",
        section="1.22",
        title="SSH package policy",
        category="ssh",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "ssh"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _ssh_service_static(rule_id: str, non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id=rule_id,
        section="1.23",
        title="SSH service policy",
        category="ssh",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "ssh"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _boot_auth_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-102000",
        section="1.32",
        title="Boot auth policy",
        category="boot",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "grub"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def _root_login_static(non_compliant: bool) -> StaticFinding:
    return StaticFinding(
        rule_id="UBTU-24-400110",
        section="1.81",
        title="Root login policy",
        category="authentication",
        rationale="r",
        recommendation="rec",
        severity="high",
        tags=("cis", "ubuntu-24", "root"),
        status=ComplianceStatus.NON_COMPLIANT if non_compliant else ComplianceStatus.COMPLIANT,
        expected_compliant_state="ok",
        verification_summary="v",
        evidence=(FindingEvidence("e", "d"),),
    )


def test_timesyncd_noncompliant_and_running_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.timesyncd_service_active = True
    rt.timesyncd_process_running = True
    rt.approved_timesync_service_active = True
    rt.approved_timesync_service_name = "chrony.service"
    out = correlate_all([_timesync_static(non_compliant=True)], rt)
    assert out[0].priority == "high"
    assert out[0].priority_adjustments
    assert any(e.label == "timesyncd_service_active" for e in out[0].runtime_evidence)


def test_timesyncd_compliant_without_alternative_adds_note_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.timesyncd_service_active = False
    rt.timesyncd_process_running = False
    rt.approved_timesync_service_active = False
    out = correlate_all([_timesync_static(non_compliant=False)], rt)
    assert out[0].priority == "medium"
    assert not out[0].priority_adjustments
    assert any("no approved alternative time synchronization service" in n for n in out[0].correlation_notes)


def test_ntp_noncompliant_and_running_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.ntp_service_active = True
    rt.ntp_process_running = True
    rt.approved_timesync_service_active = True
    rt.approved_timesync_service_name = "chrony.service"
    out = correlate_all([_ntp_static(non_compliant=True)], rt)
    assert out[0].priority == "high"
    assert out[0].priority_adjustments
    assert any(e.label == "ntp_service_active" for e in out[0].runtime_evidence)


def test_ntp_compliant_without_alternative_adds_note_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.ntp_service_active = False
    rt.ntp_process_running = False
    rt.approved_timesync_service_active = False
    out = correlate_all([_ntp_static(non_compliant=False)], rt)
    assert out[0].priority == "medium"
    assert not out[0].priority_adjustments
    assert any("no approved alternative time synchronization service" in n for n in out[0].correlation_notes)


def test_telnet_noncompliant_with_runtime_exposure_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.telnet_service_active = True
    rt.telnetd_process_running = True
    rt.telnet_port_23_listening = True
    out = correlate_all([_telnet_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments
    assert any(e.label == "telnet_port_23_listening" for e in out[0].runtime_evidence)


def test_telnet_compliant_but_port_23_open_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.telnet_service_active = False
    rt.telnetd_process_running = False
    rt.telnet_port_23_listening = True
    out = correlate_all([_telnet_static(non_compliant=False)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments
    assert any("TCP/23 is listening at runtime" in pa.reason for pa in out[0].priority_adjustments)


def test_rsyslog_install_noncompliant_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.rsyslog_service_active = False
    rt.rsyslogd_process_running = False
    rt.syslog_recently_updated = False
    out = correlate_all([_rsyslog_static("UBTU-24-100200-install", non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments
    assert any("package appears missing" in pa.reason for pa in out[0].priority_adjustments)


def test_rsyslog_compliant_but_no_log_writes_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.rsyslog_service_active = True
    rt.rsyslogd_process_running = True
    rt.syslog_recently_updated = False
    out = correlate_all([_rsyslog_static("UBTU-24-100200-active", non_compliant=False)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_firewall_install_noncompliant_without_alternative_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.ufw_installed_runtime = False
    rt.alternative_firewall_available = False
    rt.alternative_firewall_name = None
    out = correlate_all([_firewall_install_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_firewall_install_noncompliant_with_alternative_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.ufw_installed_runtime = False
    rt.alternative_firewall_available = True
    rt.alternative_firewall_name = "nftables"
    out = correlate_all([_firewall_install_static(non_compliant=True)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments
    assert any("alternative firewall framework appears present" in n for n in out[0].correlation_notes)


def test_firewall_active_noncompliant_when_ufw_inactive_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.ufw_installed_runtime = True
    rt.ufw_active_runtime = False
    rt.ufw_rules_present_runtime = False
    rt.kernel_packet_filter_loaded = False
    out = correlate_all([_firewall_active_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_firewall_active_compliant_with_missing_rules_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.ufw_installed_runtime = True
    rt.ufw_active_runtime = True
    rt.ufw_rules_present_runtime = False
    rt.kernel_packet_filter_loaded = False
    out = correlate_all([_firewall_active_static(non_compliant=False)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_apparmor_noncompliant_missing_install_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.apparmor_installed_runtime = False
    rt.apparmor_kernel_enabled = False
    rt.apparmor_profiles_loaded = False
    rt.apparmor_profiles_enforced = False
    out = correlate_all([_apparmor_install_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_apparmor_compliant_but_no_enforcement_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.apparmor_installed_runtime = True
    rt.apparmor_kernel_enabled = True
    rt.apparmor_profiles_loaded = True
    rt.apparmor_profiles_enforced = False
    out = correlate_all([_apparmor_install_static(non_compliant=False)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_apparmor_service_noncompliant_inactive_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.apparmor_service_active = False
    rt.apparmor_kernel_enabled = False
    rt.apparmor_profiles_loaded = False
    rt.apparmor_profiles_enforced = False
    out = correlate_all([_apparmor_service_static("UBTU-24-100510-active", non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_apparmor_service_compliant_with_enforced_profiles_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.apparmor_service_active = True
    rt.apparmor_kernel_enabled = True
    rt.apparmor_profiles_loaded = True
    rt.apparmor_profiles_enforced = True
    out = correlate_all([_apparmor_service_static("UBTU-24-100510-enabled", non_compliant=False)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments


def test_pwquality_noncompliant_missing_package_adds_context_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.pwquality_package_installed_runtime = False
    rt.pwquality_pam_referenced = False
    rt.pwquality_params_defined = False
    rt.pwquality_password_flow_enforced = False
    out = correlate_all([_pwquality_static(non_compliant=True)], rt)
    assert out[0].priority == "medium"
    assert not out[0].priority_adjustments
    assert any("does not appear installed" in n for n in out[0].correlation_notes)


def test_pwquality_compliant_with_enforcement_adds_positive_note():
    rt = RuntimeSnapshot(hostname="h")
    rt.pwquality_package_installed_runtime = True
    rt.pwquality_pam_referenced = True
    rt.pwquality_params_defined = True
    rt.pwquality_password_flow_enforced = True
    out = correlate_all([_pwquality_static(non_compliant=False)], rt)
    assert out[0].priority == "medium"
    assert not out[0].priority_adjustments
    assert any("active policy enforcement" in n for n in out[0].correlation_notes)


def test_ssh_install_noncompliant_without_runtime_signals_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.ssh_service_active_runtime = False
    rt.sshd_process_running_runtime = False
    rt.ssh_port_22_listening_runtime = False
    out = correlate_all([_ssh_install_static(non_compliant=True)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments
    assert any("does not appear available at runtime" in n for n in out[0].correlation_notes)


def test_ssh_install_compliant_with_full_runtime_signals_adds_positive_note():
    rt = RuntimeSnapshot(hostname="h")
    rt.ssh_service_active_runtime = True
    rt.sshd_process_running_runtime = True
    rt.ssh_port_22_listening_runtime = True
    out = correlate_all([_ssh_install_static(non_compliant=False)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments
    assert any("listening TCP/22" in n for n in out[0].correlation_notes)


def test_ssh_service_noncompliant_not_enabled_not_active_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.ssh_service_active_runtime = False
    rt.ssh_service_enabled_runtime = False
    rt.ssh_port_22_listening_runtime = False
    out = correlate_all([_ssh_service_static("UBTU-24-100810-active", non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_ssh_service_noncompliant_active_but_not_enabled_notes_only():
    rt = RuntimeSnapshot(hostname="h")
    rt.ssh_service_active_runtime = True
    rt.ssh_service_enabled_runtime = False
    rt.ssh_port_22_listening_runtime = True
    out = correlate_all([_ssh_service_static("UBTU-24-100810-enabled", non_compliant=True)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments
    assert any("not enabled for reboot persistence" in n for n in out[0].correlation_notes)


def test_boot_auth_noncompliant_missing_grub_auth_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.grub_auth_configured_runtime = False
    rt.grub_cfg_protected_runtime = False
    rt.single_user_auth_required_runtime = False
    out = correlate_all([_boot_auth_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


def test_boot_auth_compliant_with_full_signals_no_bump():
    rt = RuntimeSnapshot(hostname="h")
    rt.grub_auth_configured_runtime = True
    rt.grub_cfg_protected_runtime = True
    rt.single_user_auth_required_runtime = True
    out = correlate_all([_boot_auth_static(non_compliant=False)], rt)
    assert out[0].priority == "high"
    assert not out[0].priority_adjustments


def test_root_login_noncompliant_unlocked_bumps():
    rt = RuntimeSnapshot(hostname="h")
    rt.root_account_locked_runtime = False
    rt.ssh_permit_root_login_allowed_runtime = True
    rt.active_root_sessions_runtime = False
    out = correlate_all([_root_login_static(non_compliant=True)], rt)
    assert out[0].priority == "critical"
    assert out[0].priority_adjustments


