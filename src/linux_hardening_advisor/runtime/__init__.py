"""Runtime host-state collectors (no agents)."""

from linux_hardening_advisor.runtime.listening_ports import collect_listening_ports

__all__ = ["collect_listening_ports"]
