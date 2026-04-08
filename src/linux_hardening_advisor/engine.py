"""Orchestrates static evaluation, runtime collection, correlation, and reporting."""

from __future__ import annotations

import logging
import socket
from datetime import datetime, timezone
from pathlib import Path

from linux_hardening_advisor.correlation.engine import correlate_all
from linux_hardening_advisor.models.findings import ScanReport
from linux_hardening_advisor.models.rules import BenchmarkRule
from linux_hardening_advisor.runtime.listening_ports import collect_listening_ports
from linux_hardening_advisor.static.evaluator import evaluate_rule
from linux_hardening_advisor.static.rules_loader import load_rules_from_directory

logger = logging.getLogger(__name__)


def run_scan(
    rules_dir: Path,
    *,
    skip_runtime: bool = False,
) -> ScanReport:
    """
    Full scan: load rules → static checks → runtime snapshot → correlation → report.

    **Framework entry point** for CLI and tests.
    """
    rules = load_rules_from_directory(rules_dir)
    hostname = socket.gethostname()
    static_results = [evaluate_rule(r) for r in rules]

    if skip_runtime:
        from linux_hardening_advisor.models.runtime_state import RuntimeSnapshot

        runtime = RuntimeSnapshot(hostname=hostname)
    else:
        runtime = collect_listening_ports(hostname=hostname)

    correlated = correlate_all(static_results, runtime)
    return ScanReport(
        generated_at=datetime.now(timezone.utc),
        hostname=hostname,
        static_findings=static_results,
        correlated_findings=correlated,
        runtime_snapshot_summary=runtime.to_summary(),
    )


def load_rules_only(rules_dir: Path) -> list[BenchmarkRule]:
    """Load benchmark rules without executing a scan."""
    return load_rules_from_directory(rules_dir)
