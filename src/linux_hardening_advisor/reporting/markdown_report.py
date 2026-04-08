"""Markdown advisory report."""

from __future__ import annotations

from linux_hardening_advisor.models.findings import ScanReport


def report_to_markdown(report: ScanReport) -> str:
    """Generate a thesis-friendly Markdown document."""
    lines: list[str] = [
        "# Linux Hardening Advisory Report",
        "",
        f"- **Generated:** {report.generated_at.isoformat()}",
        f"- **Host:** `{report.hostname}`",
        "",
        "## Summary",
        "",
    ]
    for cf in report.correlated_findings:
        s = cf.static
        lines.append(f"### {s.rule_id}: {s.title}")
        lines.extend(
            [
                "",
                f"- **Category:** {s.category}",
                f"- **Compliance:** `{s.status.value}`",
                f"- **Priority (after correlation):** `{cf.priority}`",
                f"- **Severity (rule):** {s.severity}",
                "",
                "**Rationale:**",
                "",
                s.rationale,
                "",
                "**Recommendation:**",
                "",
                s.recommendation,
                "",
            ]
        )
        if cf.priority_adjustments:
            lines.append("**Priority adjustments (explainable):**")
            lines.append("")
            for pa in cf.priority_adjustments:
                lines.append(f"- {pa.reason}")
            lines.append("")
        if s.evidence:
            lines.append("**Static evidence:**")
            lines.append("")
            for ev in s.evidence:
                lines.append(f"- `{ev.label}`: {ev.detail}")
            lines.append("")
        if cf.runtime_evidence:
            lines.append("**Runtime evidence:**")
            lines.append("")
            for ev in cf.runtime_evidence:
                lines.append(f"- `{ev.label}`: {ev.detail}")
            lines.append("")
        lines.append("---")
        lines.append("")
    lines.append("## Runtime snapshot (summary)")
    lines.append("")
    lines.append("```json")
    lines.append(__import__("json").dumps(dict(report.runtime_snapshot_summary), indent=2))
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
