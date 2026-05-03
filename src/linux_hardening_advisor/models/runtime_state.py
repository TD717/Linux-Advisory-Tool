"""Runtime host state used for correlation (lightweight, no agents)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


@dataclass(frozen=True)
class ListeningEndpoint:
    """One listening socket (parsed from ``ss`` or similar)."""

    protocol: str
    local_address: str
    local_port: int | None
    process: str | None = None


@dataclass
class RuntimeSnapshot:
    """Aggregated runtime facts collected in one pass."""

    hostname: str
    listening_endpoints: list[ListeningEndpoint] = field(default_factory=list)
    raw_commands: dict[str, str] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)

    # --- Extended runtime (methodology: services, auth, logs, updates) ---
    enabled_systemd_services: list[str] = field(default_factory=list)
    """Unit names (e.g. ``ssh.service``) reported as enabled by ``systemctl``."""
    auth_log_excerpt: str = ""
    """Recent SSH / authentication-related journal or ``auth.log`` lines (bounded)."""
    failed_login_hint_count: int = 0
    """Heuristic count of likely failed login lines in ``auth_log_excerpt``."""
    security_journal_excerpt: str = ""
    """Recent higher-priority journal lines (err..alert), bounded."""
    pending_apt_upgrades: int | None = None
    """Simulated ``apt-get -s upgrade`` install count; ``None`` if unavailable."""

    # --- Time sync ---
    timesyncd_service_active: bool | None = None
    """Whether ``systemd-timesyncd.service`` is currently active (None if unknown)."""
    timesyncd_process_running: bool | None = None
    """Whether a ``systemd-timesyncd`` process is currently running (None if unknown)."""
    approved_timesync_service_active: bool | None = None
    """Whether an approved alternative time sync service (e.g. chrony) is active."""
    approved_timesync_service_name: str | None = None
    """Name of the active approved alternative service when detected."""
    ntp_service_active: bool | None = None
    """Whether ``ntp.service`` or ``ntpd.service`` is currently active."""
    ntp_process_running: bool | None = None
    """Whether an ``ntpd`` process is currently running (None if unknown)."""

    # --- Telnet ---
    telnet_service_active: bool | None = None
    """Whether telnet service stack appears active (telnet/inetd/xinetd units)."""
    telnetd_process_running: bool | None = None
    """Whether a ``telnetd`` process is currently running (None if unknown)."""
    telnet_port_23_listening: bool | None = None
    """Whether TCP/23 appears listening in the runtime socket snapshot."""

    # --- Rsyslog ---
    rsyslog_service_active: bool | None = None
    """Whether ``rsyslog.service`` is active (None if unknown)."""
    rsyslogd_process_running: bool | None = None
    """Whether an ``rsyslogd`` process is currently running (None if unknown)."""
    syslog_recently_updated: bool | None = None
    """Whether ``/var/log/syslog`` appears recently updated."""

    # --- Firewall ---
    ufw_installed_runtime: bool | None = None
    """Whether ``ufw`` appears installed from runtime package checks."""
    ufw_active_runtime: bool | None = None
    """Whether runtime ufw status appears active/enforcing."""
    ufw_rules_present_runtime: bool | None = None
    """Whether ufw reports at least one configured rule."""
    kernel_packet_filter_loaded: bool | None = None
    """Whether iptables/nftables report loaded filtering rules/tables."""
    alternative_firewall_available: bool | None = None
    """Whether another firewall framework (e.g. nftables/iptables) appears present."""
    alternative_firewall_name: str | None = None
    """Detected alternative firewall framework name, when available."""

    # --- AppArmor ---
    apparmor_installed_runtime: bool | None = None
    """Whether AppArmor package/userspace tooling appears installed."""
    apparmor_service_active: bool | None = None
    """Whether ``apparmor.service`` appears active at runtime."""
    apparmor_kernel_enabled: bool | None = None
    """Whether AppArmor appears loaded and enabled in the kernel."""
    apparmor_profiles_loaded: bool | None = None
    """Whether AppArmor reports any loaded profiles."""
    apparmor_profiles_enforced: bool | None = None
    """Whether AppArmor reports profiles in enforce mode."""

    # --- PAM pwquality ---
    pwquality_package_installed_runtime: bool | None = None
    """Whether ``libpam-pwquality`` appears installed from runtime package checks."""
    pwquality_pam_referenced: bool | None = None
    """Whether ``pam_pwquality.so`` is referenced in PAM configuration."""
    pwquality_params_defined: bool | None = None
    """Whether pwquality parameters (minlen/credit/class rules) appear defined."""
    pwquality_password_flow_enforced: bool | None = None
    """Whether password-change PAM stack appears to include pwquality enforcement."""

    # --- SSH ---
    ssh_service_active_runtime: bool | None = None
    """Whether ``ssh.service`` appears active at runtime."""
    ssh_service_enabled_runtime: bool | None = None
    """Whether ``ssh.service`` appears enabled for boot at runtime."""
    sshd_process_running_runtime: bool | None = None
    """Whether an ``sshd`` process appears running at runtime."""
    ssh_port_22_listening_runtime: bool | None = None
    """Whether TCP/22 appears listening in runtime socket data."""

    # --- Boot auth ---
    grub_auth_configured_runtime: bool | None = None
    """Whether effective GRUB config appears to contain auth directives."""
    grub_cfg_protected_runtime: bool | None = None
    """Whether ``/boot/grub/grub.cfg`` appears protected from easy modification."""
    single_user_auth_required_runtime: bool | None = None
    """Whether rescue/emergency unit definitions appear to require sulogin auth."""

    # --- Root login ---
    root_account_locked_runtime: bool | None = None
    """Whether local root account appears locked for password logins."""
    ssh_permit_root_login_allowed_runtime: bool | None = None
    """Whether sshd runtime configuration appears to allow direct root login."""
    active_root_sessions_runtime: bool | None = None
    """Whether active root login sessions are detected via ``who``."""

    collection_notes: list[str] = field(default_factory=list)
    """Non-fatal issues (permissions, missing tools)."""

    def to_summary(self) -> Mapping[str, Any]:
        """Structured summary for JSON/Markdown reports."""
        return {
            "hostname": self.hostname,
            "listening_count": len(self.listening_endpoints),
            "listening_endpoints": [
                {
                    "protocol": e.protocol,
                    "local_address": e.local_address,
                    "local_port": e.local_port,
                    "process": e.process,
                }
                for e in self.listening_endpoints
            ],
            "enabled_service_count": len(self.enabled_systemd_services),
            "enabled_systemd_services_sample": self.enabled_systemd_services[:80],
            "failed_login_hint_count": self.failed_login_hint_count,
            "auth_log_excerpt_preview": self.auth_log_excerpt[:2000],
            "security_journal_excerpt_preview": self.security_journal_excerpt[:2000],
            "pending_apt_upgrades": self.pending_apt_upgrades,
            "timesyncd_service_active": self.timesyncd_service_active,
            "timesyncd_process_running": self.timesyncd_process_running,
            "approved_timesync_service_active": self.approved_timesync_service_active,
            "approved_timesync_service_name": self.approved_timesync_service_name,
            "ntp_service_active": self.ntp_service_active,
            "ntp_process_running": self.ntp_process_running,
            "telnet_service_active": self.telnet_service_active,
            "telnetd_process_running": self.telnetd_process_running,
            "telnet_port_23_listening": self.telnet_port_23_listening,
            "rsyslog_service_active": self.rsyslog_service_active,
            "rsyslogd_process_running": self.rsyslogd_process_running,
            "syslog_recently_updated": self.syslog_recently_updated,
            "ufw_installed_runtime": self.ufw_installed_runtime,
            "ufw_active_runtime": self.ufw_active_runtime,
            "ufw_rules_present_runtime": self.ufw_rules_present_runtime,
            "kernel_packet_filter_loaded": self.kernel_packet_filter_loaded,
            "alternative_firewall_available": self.alternative_firewall_available,
            "alternative_firewall_name": self.alternative_firewall_name,
            "apparmor_installed_runtime": self.apparmor_installed_runtime,
            "apparmor_service_active": self.apparmor_service_active,
            "apparmor_kernel_enabled": self.apparmor_kernel_enabled,
            "apparmor_profiles_loaded": self.apparmor_profiles_loaded,
            "apparmor_profiles_enforced": self.apparmor_profiles_enforced,
            "pwquality_package_installed_runtime": self.pwquality_package_installed_runtime,
            "pwquality_pam_referenced": self.pwquality_pam_referenced,
            "pwquality_params_defined": self.pwquality_params_defined,
            "pwquality_password_flow_enforced": self.pwquality_password_flow_enforced,
            "ssh_service_active_runtime": self.ssh_service_active_runtime,
            "ssh_service_enabled_runtime": self.ssh_service_enabled_runtime,
            "sshd_process_running_runtime": self.sshd_process_running_runtime,
            "ssh_port_22_listening_runtime": self.ssh_port_22_listening_runtime,
            "grub_auth_configured_runtime": self.grub_auth_configured_runtime,
            "grub_cfg_protected_runtime": self.grub_cfg_protected_runtime,
            "single_user_auth_required_runtime": self.single_user_auth_required_runtime,
            "root_account_locked_runtime": self.root_account_locked_runtime,
            "ssh_permit_root_login_allowed_runtime": self.ssh_permit_root_login_allowed_runtime,
            "active_root_sessions_runtime": self.active_root_sessions_runtime,
            "collection_notes": list(self.collection_notes),
            "metadata": dict(self.metadata),
        }
