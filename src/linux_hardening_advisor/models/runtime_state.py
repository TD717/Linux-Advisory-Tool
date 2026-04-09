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
            "collection_notes": list(self.collection_notes),
            "metadata": dict(self.metadata),
        }
