"""Human-readable terminal summary."""

from __future__ import annotations

import sys

from linux_hardening_advisor.models.findings import ScanReport


def print_terminal_summary(report: ScanReport, file=sys.stdout) -> None:
    """Print a short advisory summary for interactive use."""
    print(f"Linux Hardening Advisor — {report.generated_at.isoformat()}", file=file)
    print(f"Host: {report.hostname}", file=file)
    print("", file=file)
    print("Correlated findings:", file=file)
    for cf in report.correlated_findings:
        s = cf.static
        print(f"  [{cf.priority.upper()}] {s.rule_id} — {s.title}", file=file)
        print(f"      status: {s.status.value}", file=file)
        if cf.priority_adjustments:
            for pa in cf.priority_adjustments:
                print(f"      priority note: {pa.reason}", file=file)
        print("", file=file)
