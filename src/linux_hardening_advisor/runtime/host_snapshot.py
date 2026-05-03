"""
Full runtime snapshot: listening ports, enabled services, auth/journal excerpts, apt simulation.

All collection stays bounded and best-effort; failures become ``collection_notes`` entries.
"""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

from linux_hardening_advisor.collectors.subprocess_runner import run_argv, run_shell
from linux_hardening_advisor.models.runtime_state import RuntimeSnapshot
from linux_hardening_advisor.runtime.listening_ports import collect_listening_ports

logger = logging.getLogger(__name__)

_MAX_ENABLED_SERVICES = 400
_MAX_AUTH_CHARS = 12000
_MAX_JOURNAL_CHARS = 8000
_FAILED_PATTERNS = (
    "failed password",
    "authentication failure",
    "invalid user",
    "connection closed by authenticating user",
)
_APPROVED_TIME_SYNC_UNITS = ("chrony.service", "chronyd.service")
_NTP_UNITS = ("ntp.service", "ntpd.service")
_TELNET_UNITS = ("telnet.service", "telnet.socket", "inetd.service", "xinetd.service")
_ALT_FIREWALL_BINARIES = (("nftables", "nft"), ("iptables", "iptables"))
_SYSLOG_PATH = Path("/var/log/syslog")
_SYSLOG_RECENT_WINDOW_S = 3600
_GRUB_CFG_PATH = Path("/boot/grub/grub.cfg")
_PAM_COMMON_PASSWORD = Path("/etc/pam.d/common-password")
_PWQUALITY_CONF = Path("/etc/security/pwquality.conf")
_PWQUALITY_CONF_DIR = Path("/etc/security/pwquality.conf.d")
_PWQUALITY_PARAM_KEYS = ("minlen", "minclass", "dcredit", "ucredit", "lcredit", "ocredit")


def collect_full_snapshot(hostname: str | None = None) -> RuntimeSnapshot:
    """Collect all lightweight runtime facts for hybrid correlation and reports."""
    snap = collect_listening_ports(hostname=hostname)
    _collect_enabled_services(snap)
    _collect_auth_excerpt(snap)
    _collect_security_journal(snap)
    _collect_pending_apt(snap)
    _collect_timesync_runtime(snap)
    _collect_telnet_runtime(snap)
    _collect_rsyslog_runtime(snap)
    _collect_firewall_runtime(snap)
    _collect_apparmor_runtime(snap)
    _collect_pwquality_runtime(snap)
    _collect_ssh_runtime(snap)
    _collect_boot_auth_runtime(snap)
    _collect_root_login_runtime(snap)
    _count_failed_login_hints(snap)
    return snap


def _collect_enabled_services(snap: RuntimeSnapshot) -> None:
    """Populate enabled systemd services from list-unit-files output."""
    r = run_argv(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-pager",
        ],
        timeout_s=90.0,
    )
    snap.raw_commands["systemctl_list_unit_files_enabled"] = (r.stdout or "")[:25000]
    if r.returncode != 0:
        snap.collection_notes.append(
            f"enabled-services: systemctl list-unit-files failed (rc={r.returncode})"
        )
        return
    units: list[str] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if not line or line.startswith("UNIT"):
            continue
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "enabled":
            units.append(parts[0])
        elif len(parts) == 1 and parts[0].endswith(".service"):
            units.append(parts[0])
    snap.enabled_systemd_services = units[:_MAX_ENABLED_SERVICES]
    snap.metadata["enabled_services_source"] = "systemctl list-unit-files --type=service --state=enabled"


def _collect_auth_excerpt(snap: RuntimeSnapshot) -> None:
    """Capture bounded SSH/auth logs from journalctl or auth.log fallback."""
    r = run_argv(
        [
            "journalctl",
            "-u",
            "ssh",
            "-u",
            "ssh.service",
            "-u",
            "sshd",
            "-u",
            "sshd.service",
            "--since",
            "24 hours ago",
            "-n",
            "150",
            "--no-pager",
        ],
        timeout_s=45.0,
    )
    text = (r.stdout or "").strip()
    source = "journalctl ssh units"
    if r.returncode != 0 or not text:
        alt = Path("/var/log/auth.log")
        if alt.is_file():
            try:
                raw = alt.read_text(encoding="utf-8", errors="replace")
                lines = raw.splitlines()[-120:]
                text = "\n".join(lines)
                source = "/var/log/auth.log tail"
            except OSError as exc:
                snap.collection_notes.append(f"auth: cannot read auth.log ({exc})")
                text = ""
        else:
            if r.returncode != 0:
                snap.collection_notes.append(
                    f"auth: journalctl ssh units failed (rc={r.returncode}); no auth.log"
                )
    snap.auth_log_excerpt = text[:_MAX_AUTH_CHARS]
    snap.metadata["auth_log_source"] = source


def _collect_security_journal(snap: RuntimeSnapshot) -> None:
    """Capture a bounded recent err..alert journal excerpt."""
    r = run_argv(
        [
            "journalctl",
            "-p",
            "err..alert",
            "--since",
            "24 hours ago",
            "-n",
            "60",
            "--no-pager",
        ],
        timeout_s=45.0,
    )
    if r.returncode != 0:
        snap.collection_notes.append(f"security-journal: journalctl err..alert failed (rc={r.returncode})")
        return
    snap.security_journal_excerpt = (r.stdout or "")[:_MAX_JOURNAL_CHARS]
    snap.metadata["security_journal_source"] = "journalctl -p err..alert --since 24 hours ago"


def _collect_pending_apt(snap: RuntimeSnapshot) -> None:
    """Estimate pending apt upgrades using a dry-run install count."""
    if not Path("/usr/bin/apt-get").is_file():
        snap.pending_apt_upgrades = None
        snap.collection_notes.append("updates: apt-get not found (non-Debian or minimal image)")
        return
    r = run_shell("apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true", timeout_s=120.0)
    raw = (r.stdout or "").strip()
    try:
        n = int(raw.splitlines()[-1] if raw else "0")
    except ValueError:
        n = 0
    snap.pending_apt_upgrades = n
    snap.metadata["pending_apt_source"] = "apt-get -s upgrade (Inst lines count)"


def _count_failed_login_hints(snap: RuntimeSnapshot) -> None:
    """Count heuristic failed-auth patterns inside the auth excerpt."""
    if not snap.auth_log_excerpt:
        snap.failed_login_hint_count = 0
        return
    lower = snap.auth_log_excerpt.lower()
    n = 0
    for pat in _FAILED_PATTERNS:
        n += len(re.findall(re.escape(pat), lower))
    snap.failed_login_hint_count = n


def _collect_timesync_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime status used for time-sync policy correlation."""
    snap.timesyncd_service_active = _is_service_active("systemd-timesyncd.service")
    r = run_argv(["pgrep", "-x", "systemd-timesyncd"], timeout_s=20.0)
    snap.raw_commands["pgrep_systemd_timesyncd"] = (r.stdout or "")[:4000]
    if r.returncode == 0:
        snap.timesyncd_process_running = True
    elif r.returncode == 1:
        snap.timesyncd_process_running = False
    else:
        snap.timesyncd_process_running = None
        snap.collection_notes.append(f"timesyncd: pgrep failed (rc={r.returncode})")

    snap.approved_timesync_service_active = False
    snap.approved_timesync_service_name = None
    for unit in _APPROVED_TIME_SYNC_UNITS:
        active = _is_service_active(unit)
        if active is True:
            snap.approved_timesync_service_active = True
            snap.approved_timesync_service_name = unit
            break
        if active is None and snap.approved_timesync_service_active is False:
            snap.approved_timesync_service_active = None

    ntp_states = [_is_service_active(unit) for unit in _NTP_UNITS]
    if any(state is True for state in ntp_states):
        snap.ntp_service_active = True
    elif all(state is False for state in ntp_states):
        snap.ntp_service_active = False
    else:
        snap.ntp_service_active = None

    ntp_proc = run_argv(["pgrep", "-x", "ntpd"], timeout_s=20.0)
    snap.raw_commands["pgrep_ntpd"] = (ntp_proc.stdout or "")[:4000]
    if ntp_proc.returncode == 0:
        snap.ntp_process_running = True
    elif ntp_proc.returncode == 1:
        snap.ntp_process_running = False
    else:
        snap.ntp_process_running = None
        snap.collection_notes.append(f"ntp: pgrep failed (rc={ntp_proc.returncode})")


def _is_service_active(unit: str) -> bool | None:
    """Return ``systemctl is-active`` state as bool; None when unavailable/error."""
    r = run_argv(["systemctl", "is-active", unit], timeout_s=30.0)
    out = (r.stdout or "").strip()
    if r.returncode == 0:
        return out == "active"
    if r.returncode in (3, 4) or out in {"inactive", "failed", "unknown"}:
        return False
    return None


def _is_service_enabled(unit: str) -> bool | None:
    """Return systemd enabled-state as bool, None when unknown/error."""
    r = run_argv(["systemctl", "is-enabled", unit], timeout_s=30.0)
    out = (r.stdout or "").strip().lower()
    if r.returncode == 0:
        return out in {"enabled", "enabled-runtime", "static"}
    if out in {"disabled", "masked", "indirect", "generated", "transient"}:
        return False
    if r.returncode in (1, 4):
        return False
    return None


def _collect_telnet_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime status used for telnet package/exposure correlation."""
    telnet_states = [_is_service_active(unit) for unit in _TELNET_UNITS]
    if any(state is True for state in telnet_states):
        snap.telnet_service_active = True
    elif all(state is False for state in telnet_states):
        snap.telnet_service_active = False
    else:
        snap.telnet_service_active = None

    telnet_proc = run_argv(["pgrep", "-x", "telnetd"], timeout_s=20.0)
    snap.raw_commands["pgrep_telnetd"] = (telnet_proc.stdout or "")[:4000]
    if telnet_proc.returncode == 0:
        snap.telnetd_process_running = True
    elif telnet_proc.returncode == 1:
        snap.telnetd_process_running = False
    else:
        snap.telnetd_process_running = None
        snap.collection_notes.append(f"telnet: pgrep failed (rc={telnet_proc.returncode})")

    snap.telnet_port_23_listening = any(
        e.protocol == "tcp" and e.local_port == 23 for e in snap.listening_endpoints
    )


def _collect_rsyslog_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime status used for rsyslog install/enabled/active correlation."""
    snap.rsyslog_service_active = _is_service_active("rsyslog.service")

    rsyslog_proc = run_argv(["pgrep", "-x", "rsyslogd"], timeout_s=20.0)
    snap.raw_commands["pgrep_rsyslogd"] = (rsyslog_proc.stdout or "")[:4000]
    if rsyslog_proc.returncode == 0:
        snap.rsyslogd_process_running = True
    elif rsyslog_proc.returncode == 1:
        snap.rsyslogd_process_running = False
    else:
        snap.rsyslogd_process_running = None
        snap.collection_notes.append(f"rsyslog: pgrep failed (rc={rsyslog_proc.returncode})")

    if not _SYSLOG_PATH.exists():
        snap.syslog_recently_updated = False
        return
    try:
        st = _SYSLOG_PATH.stat()
    except OSError as exc:
        snap.syslog_recently_updated = None
        snap.collection_notes.append(f"rsyslog: cannot stat /var/log/syslog ({exc})")
        return
    age_s = max(0.0, time.time() - st.st_mtime)
    snap.syslog_recently_updated = age_s <= _SYSLOG_RECENT_WINDOW_S
    snap.metadata["syslog_recent_window_seconds"] = _SYSLOG_RECENT_WINDOW_S


def _collect_firewall_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime package/framework presence for firewall install correlation."""
    snap.ufw_installed_runtime = _is_package_installed("ufw")
    _collect_ufw_runtime_state(snap)
    _collect_kernel_filter_runtime(snap)
    snap.alternative_firewall_available = False
    snap.alternative_firewall_name = None
    for name, binary in _ALT_FIREWALL_BINARIES:
        if _has_command(binary):
            snap.alternative_firewall_available = True
            snap.alternative_firewall_name = name
            return


def _is_package_installed(package: str) -> bool | None:
    """Return True when dpkg reports package installed, None if probe failed."""
    r = run_argv(["dpkg-query", "-W", "-f=${Status}", package], timeout_s=30.0)
    out = (r.stdout or "").strip()
    if r.returncode == 0:
        return "install ok installed" in out
    if r.returncode == 1 and not out:
        return False
    return None


def _has_command(binary: str) -> bool:
    """Check whether a command exists in PATH using shell builtins."""
    r = run_shell(f"command -v {binary} >/dev/null 2>&1 && echo yes || echo no", timeout_s=20.0)
    return (r.stdout or "").strip().endswith("yes")


def _collect_ufw_runtime_state(snap: RuntimeSnapshot) -> None:
    """Collect ufw active state and basic rule presence from status output."""
    r = run_shell("ufw status 2>/dev/null || true", timeout_s=30.0)
    status = (r.stdout or "").strip()
    snap.raw_commands["ufw_status"] = status[:8000]
    if not status:
        snap.ufw_active_runtime = False if snap.ufw_installed_runtime is False else None
        snap.ufw_rules_present_runtime = None
        return
    lower = status.lower()
    snap.ufw_active_runtime = "status: active" in lower
    if "status: inactive" in lower:
        snap.ufw_rules_present_runtime = False
        return
    lines = [ln.strip() for ln in status.splitlines() if ln.strip()]
    # UFW with rules typically includes rows after headers containing ALLOW/DENY/REJECT.
    has_rule_line = any(("allow" in ln.lower() or "deny" in ln.lower() or "reject" in ln.lower()) for ln in lines)
    snap.ufw_rules_present_runtime = has_rule_line


def _collect_kernel_filter_runtime(snap: RuntimeSnapshot) -> None:
    """Collect simple indicator that packet filter rules exist in kernel backends."""
    nft_out = ""
    ipt_out = ""
    if _has_command("nft"):
        nft = run_shell("nft list ruleset 2>/dev/null || true", timeout_s=30.0)
        nft_out = (nft.stdout or "").strip()
        snap.raw_commands["nft_list_ruleset"] = nft_out[:8000]
    if _has_command("iptables"):
        ipt = run_shell("iptables -S 2>/dev/null || true", timeout_s=30.0)
        ipt_out = (ipt.stdout or "").strip()
        snap.raw_commands["iptables_S"] = ipt_out[:8000]
    nft_loaded = "table " in nft_out
    ipt_loaded = any(line.startswith("-A ") for line in ipt_out.splitlines())
    snap.kernel_packet_filter_loaded = nft_loaded or ipt_loaded


def _collect_apparmor_runtime(snap: RuntimeSnapshot) -> None:
    """Collect AppArmor runtime installation/enablement/profile signals."""
    snap.apparmor_installed_runtime = _is_package_installed("apparmor")
    snap.apparmor_service_active = _is_service_active("apparmor.service")

    kernel_enabled = None
    enabled_path = Path("/sys/module/apparmor/parameters/enabled")
    if enabled_path.exists():
        try:
            val = enabled_path.read_text(encoding="utf-8", errors="replace").strip().lower()
            kernel_enabled = val.startswith("y")
        except OSError as exc:
            snap.collection_notes.append(f"apparmor: cannot read kernel enabled flag ({exc})")
    snap.apparmor_kernel_enabled = kernel_enabled

    status_cmd = "aa-status 2>/dev/null || apparmor_status 2>/dev/null || true"
    r = run_shell(status_cmd, timeout_s=40.0)
    out = (r.stdout or "").strip()
    snap.raw_commands["aa_status"] = out[:12000]
    if not out:
        # Keep unknown when tools are unavailable; kernel flag still carries value if present.
        snap.apparmor_profiles_loaded = None
        snap.apparmor_profiles_enforced = None
        if snap.apparmor_installed_runtime is True and snap.apparmor_kernel_enabled is None:
            snap.collection_notes.append("apparmor: status tool unavailable; profile state unknown")
        return

    low = out.lower()
    if "module is loaded" in low:
        snap.apparmor_kernel_enabled = True
    if "module is not loaded" in low or "apparmor is disabled" in low:
        snap.apparmor_kernel_enabled = False

    loaded_count = _extract_leading_int(low, "profiles are loaded")
    enforce_count = _extract_leading_int(low, "profiles are in enforce mode")
    complain_count = _extract_leading_int(low, "profiles are in complain mode")
    if loaded_count is not None:
        snap.apparmor_profiles_loaded = loaded_count > 0
    elif "0 profiles are loaded" in low:
        snap.apparmor_profiles_loaded = False

    if enforce_count is not None:
        snap.apparmor_profiles_enforced = enforce_count > 0
    elif complain_count is not None and complain_count > 0:
        snap.apparmor_profiles_enforced = False


def _extract_leading_int(text: str, suffix: str) -> int | None:
    """Extract integer value from lines like '12 profiles are loaded'."""
    m = re.search(rf"(\d+)\s+{re.escape(suffix)}", text)
    if not m:
        return None
    try:
        return int(m.group(1))
    except ValueError:
        return None


def _collect_pwquality_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime usage/enforcement signals for libpam-pwquality."""
    snap.pwquality_package_installed_runtime = _is_package_installed("libpam-pwquality")

    pam_text = _read_text_if_file(_PAM_COMMON_PASSWORD)
    if pam_text is None:
        snap.pwquality_pam_referenced = False
        snap.pwquality_password_flow_enforced = False
    else:
        low = pam_text.lower()
        has_ref = "pam_pwquality.so" in low
        snap.pwquality_pam_referenced = has_ref
        flow_line = _pam_password_line_with_pwquality(low)
        snap.pwquality_password_flow_enforced = flow_line
        snap.raw_commands["pam_common_password_excerpt"] = pam_text[:4000]

    conf_texts: list[str] = []
    conf = _read_text_if_file(_PWQUALITY_CONF)
    if conf is not None:
        conf_texts.append(conf)
    if _PWQUALITY_CONF_DIR.is_dir():
        for p in sorted(_PWQUALITY_CONF_DIR.glob("*.conf")):
            txt = _read_text_if_file(p)
            if txt is not None:
                conf_texts.append(txt)
    combined = "\n".join(conf_texts).lower()
    snap.pwquality_params_defined = _has_pwquality_params(combined) if combined else False
    if combined:
        snap.raw_commands["pwquality_conf_excerpt"] = combined[:4000]


def _read_text_if_file(path: Path) -> str | None:
    """Read UTF-8 text from file path, returning None on absence/read errors."""
    if not path.is_file():
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _pam_password_line_with_pwquality(text_lower: str) -> bool:
    """Return True when PAM password stack line includes pam_pwquality.so."""
    for raw in text_lower.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("password") and "pam_pwquality.so" in line:
            return True
    return False


def _has_pwquality_params(text_lower: str) -> bool:
    """Return True when any known pwquality parameter key is explicitly set."""
    for raw in text_lower.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        for key in _PWQUALITY_PARAM_KEYS:
            if line.startswith(f"{key}=") or line.startswith(f"{key} "):
                return True
    return False


def _collect_ssh_runtime(snap: RuntimeSnapshot) -> None:
    """Collect SSH runtime availability signals for install/service correlation."""
    snap.ssh_service_active_runtime = _is_service_active("ssh.service")
    snap.ssh_service_enabled_runtime = _is_service_enabled("ssh.service")
    r = run_argv(["pgrep", "-x", "sshd"], timeout_s=20.0)
    snap.raw_commands["pgrep_sshd"] = (r.stdout or "")[:4000]
    if r.returncode == 0:
        snap.sshd_process_running_runtime = True
    elif r.returncode == 1:
        snap.sshd_process_running_runtime = False
    else:
        snap.sshd_process_running_runtime = None
        snap.collection_notes.append(f"ssh: pgrep failed (rc={r.returncode})")
    snap.ssh_port_22_listening_runtime = any(
        e.protocol == "tcp" and e.local_port == 22 for e in snap.listening_endpoints
    )


def _collect_boot_auth_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime signals for GRUB/single-user authentication enforcement."""
    text = _read_text_if_file(_GRUB_CFG_PATH)
    if text is None:
        snap.grub_auth_configured_runtime = False
        snap.grub_cfg_protected_runtime = False
    else:
        low = text.lower()
        snap.grub_auth_configured_runtime = ("password_pbkdf2" in low) or ("set superusers" in low)
        try:
            st = _GRUB_CFG_PATH.stat()
            mode = st.st_mode & 0o777
            snap.grub_cfg_protected_runtime = (st.st_uid == 0) and mode <= 0o600
            snap.metadata["grub_cfg_mode_octal"] = oct(mode)
        except OSError as exc:
            snap.grub_cfg_protected_runtime = None
            snap.collection_notes.append(f"boot: cannot stat grub.cfg ({exc})")
        snap.raw_commands["grub_cfg_auth_excerpt"] = low[:4000]

    r = run_shell("systemctl cat rescue.service emergency.service 2>/dev/null || true", timeout_s=30.0)
    unit_text = (r.stdout or "").lower()
    snap.raw_commands["systemctl_cat_rescue_emergency"] = unit_text[:8000]
    if not unit_text.strip():
        snap.single_user_auth_required_runtime = None
        return
    # systemd rescue/emergency auth typically uses sulogin; absence suggests weaker protection.
    snap.single_user_auth_required_runtime = "sulogin" in unit_text


def _collect_root_login_runtime(snap: RuntimeSnapshot) -> None:
    """Collect runtime signals for root-account and SSH direct-root login controls."""
    r = run_argv(["passwd", "-S", "root"], timeout_s=20.0)
    out = (r.stdout or "").strip()
    snap.raw_commands["passwd_S_root"] = out[:1000]
    if r.returncode == 0 and out:
        parts = out.split()
        snap.root_account_locked_runtime = len(parts) >= 2 and parts[1] == "L"
    else:
        snap.root_account_locked_runtime = None
        snap.collection_notes.append("root: cannot determine passwd -S lock state")

    sshd_t = run_shell("sshd -T 2>/dev/null | grep -i '^permitrootlogin ' || true", timeout_s=30.0)
    line = (sshd_t.stdout or "").strip().lower()
    snap.raw_commands["sshd_T_permitrootlogin"] = line[:2000]
    if not line:
        snap.ssh_permit_root_login_allowed_runtime = None
    elif "permitrootlogin no" in line:
        snap.ssh_permit_root_login_allowed_runtime = False
    else:
        snap.ssh_permit_root_login_allowed_runtime = True

    who = run_argv(["who"], timeout_s=20.0)
    who_out = (who.stdout or "").strip()
    snap.raw_commands["who"] = who_out[:4000]
    snap.active_root_sessions_runtime = any(
        ln.split()[0] == "root" for ln in who_out.splitlines() if ln.split()
    )

