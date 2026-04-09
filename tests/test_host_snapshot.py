"""Runtime snapshot helpers (auth hint counting)."""

from linux_hardening_advisor.models.runtime_state import RuntimeSnapshot
from linux_hardening_advisor.runtime import host_snapshot as hs


def test_failed_login_hint_count():
    snap = RuntimeSnapshot(hostname="test")
    snap.auth_log_excerpt = "Failed password for invalid user x from 1.2.3.4\nAuthentication failure"
    hs._count_failed_login_hints(snap)
    assert snap.failed_login_hint_count >= 2


def test_failed_login_hint_empty():
    snap = RuntimeSnapshot(hostname="test")
    snap.auth_log_excerpt = ""
    hs._count_failed_login_hints(snap)
    assert snap.failed_login_hint_count == 0
