"""Small command wrappers used by runtime collectors.

This module keeps shell/system command details in one place so collector logic
can stay focused on "what" is collected instead of "how" commands are invoked.
"""

from __future__ import annotations

from linux_hardening_advisor.collectors.subprocess_runner import run_argv, run_shell


def run_systemctl_list_enabled_services():
    """List enabled systemd service unit files."""
    return run_argv(
        [
            "systemctl",
            "list-unit-files",
            "--type=service",
            "--state=enabled",
            "--no-pager",
        ],
        timeout_s=90.0,
    )


def run_auth_journal_excerpt():
    """Collect bounded auth/ssh journal excerpt."""
    return run_argv(
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


def run_security_journal_excerpt():
    """Collect bounded err..alert journal excerpt."""
    return run_argv(
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


def run_pending_apt_count():
    """Simulate apt upgrades and count Inst lines."""
    return run_shell("apt-get -s upgrade 2>/dev/null | grep -c '^Inst ' || true", timeout_s=120.0)


def run_command_exists_check(binary: str):
    """Check whether command exists in PATH."""
    return run_shell(f"command -v {binary} >/dev/null 2>&1 && echo yes || echo no", timeout_s=20.0)


def run_ufw_status():
    """Get ufw status output."""
    return run_shell("ufw status 2>/dev/null || true", timeout_s=30.0)


def run_nft_ruleset():
    """Get nftables ruleset."""
    return run_shell("nft list ruleset 2>/dev/null || true", timeout_s=30.0)


def run_iptables_rules():
    """Get iptables rules."""
    return run_shell("iptables -S 2>/dev/null || true", timeout_s=30.0)


def run_apparmor_status():
    """Get AppArmor status from available command."""
    return run_shell("aa-status 2>/dev/null || apparmor_status 2>/dev/null || true", timeout_s=40.0)


def run_systemctl_cat_rescue_emergency():
    """Get rescue/emergency systemd units."""
    return run_shell("systemctl cat rescue.service emergency.service 2>/dev/null || true", timeout_s=30.0)


def run_sshd_permit_root_login_line():
    """Get effective sshd PermitRootLogin line."""
    return run_shell("sshd -T 2>/dev/null | grep -i '^permitrootlogin ' || true", timeout_s=30.0)


def run_who():
    """Get active login sessions."""
    return run_argv(["who"], timeout_s=20.0)
