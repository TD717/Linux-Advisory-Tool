"""
Full runtime snapshot: listening ports, enabled services, auth/journal excerpts, apt simulation.

All collection stays bounded and best-effort; failures become ``collection_notes`` entries.
"""

from __future__ import annotations

import logging
import re
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


def collect_full_snapshot(hostname: str | None = None) -> RuntimeSnapshot:
    """Collect all lightweight runtime facts for hybrid correlation and reports."""
    snap = collect_listening_ports(hostname=hostname)
    _collect_enabled_services(snap)
    _collect_auth_excerpt(snap)
    _collect_security_journal(snap)
    _collect_pending_apt(snap)
    _count_failed_login_hints(snap)
    return snap


def _collect_enabled_services(snap: RuntimeSnapshot) -> None:
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
    if not snap.auth_log_excerpt:
        snap.failed_login_hint_count = 0
        return
    lower = snap.auth_log_excerpt.lower()
    n = 0
    for pat in _FAILED_PATTERNS:
        n += len(re.findall(re.escape(pat), lower))
    snap.failed_login_hint_count = n
