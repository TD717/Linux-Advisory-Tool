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
            "metadata": dict(self.metadata),
        }
