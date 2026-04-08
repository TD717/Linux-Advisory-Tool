"""Collect listening TCP/UDP sockets using ``ss`` (preferred) or ``netstat``."""

from __future__ import annotations

import logging
import socket
from typing import Iterable

from linux_hardening_advisor.collectors.subprocess_runner import run_argv
from linux_hardening_advisor.models.runtime_state import ListeningEndpoint, RuntimeSnapshot

logger = logging.getLogger(__name__)


def collect_listening_ports(hostname: str | None = None) -> RuntimeSnapshot:
    """
    Parse ``ss -tulnp`` (or fallback) into ``ListeningEndpoint`` records.
    
    """
    hn = hostname or socket.gethostname()
    snap = RuntimeSnapshot(hostname=hn)
    text, source = _run_ss_listen()
    snap.metadata["listening_source"] = source
    snap.raw_commands["ss_or_netstat"] = text[:20000]
    snap.listening_endpoints.extend(_parse_ss_lines(text))
    return snap


def _run_ss_listen() -> tuple[str, str]:
    r = run_argv(["ss", "-tulnp"], timeout_s=60.0)
    if r.returncode == 0 and (r.stdout or "").strip():
        return r.stdout or "", "ss -tulnp"
    r2 = run_argv(["netstat", "-tulnp"], timeout_s=60.0)
    if r2.returncode == 0:
        return r2.stdout or "", "netstat -tulnp"
    logger.warning("Neither ss nor netstat produced usable output; stderr=%s", r.stderr or r2.stderr)
    return (r.stdout or "") + (r2.stdout or ""), "ss/netstat (partial)"


def _parse_ss_lines(text: str) -> Iterable[ListeningEndpoint]:
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("Netid") or line.startswith("Active"):
            continue
        ep = _parse_one_line(line)
        if ep is not None:
            yield ep


def _parse_one_line(line: str) -> ListeningEndpoint | None:
    # Typical ``ss -tulnp``: Netid State Recv-Q Send-Q Local Peer Process
    parts = line.split()
    if len(parts) < 6:
        return None
    proto = parts[0].lower()
    state = parts[1]
    if state not in ("LISTEN", "UNCONN"):
        return None
    local = parts[4]
    proc = " ".join(parts[6:]) if len(parts) > 6 else None
    addr, port = _split_host_port(local)
    return ListeningEndpoint(protocol=proto, local_address=addr, local_port=port, process=proc)


def _split_host_port(local: str) -> tuple[str, int | None]:
    if local == "*:*" or local == "[::]:*":
        return local, None
    if local.startswith("["):
        # [::1]:22
        rb = local.rfind("]:")
        if rb != -1:
            host = local[: rb + 1]
            try:
                return host, int(local[rb + 2 :])
            except ValueError:
                return local, None
    if ":" in local:
        host, _, port_s = local.rpartition(":")
        try:
            return host, int(port_s)
        except ValueError:
            return local, None
    return local, None
