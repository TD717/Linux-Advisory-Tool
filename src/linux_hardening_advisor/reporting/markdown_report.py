"""Markdown advisory report."""

from __future__ import annotations

from linux_hardening_advisor.models.findings import ScanReport


def report_to_markdown(report: ScanReport) -> str:
    """Generate a thesis-friendly Markdown document."""
    snap = dict(report.runtime_snapshot_summary)
    listen_n = snap.get("listening_count", "—")
    listen_src = "unknown"
    meta = snap.get("metadata") or {}
    if isinstance(meta, dict):
        listen_src = meta.get("listening_source", listen_src)
    svc_n = snap.get("enabled_service_count", "—")
    auth_hints = snap.get("failed_login_hint_count", "—")
    pending = snap.get("pending_apt_upgrades", "—")
    notes = snap.get("collection_notes") or []

    lines: list[str] = [
        "# Linux Hardening Advisory Report",
        "",
        f"- **Generated:** {report.generated_at.isoformat()}",
        f"- **Host:** `{report.hostname}`",
        "",
        "## How this report is built (hybrid model)",
        "",
        "1. **Static (benchmark) evidence** — each control is evaluated from your YAML/JSON rules "
        "(commands, `systemctl`, `dpkg`, config greps, etc.). This appears under *Static evidence* per finding.",
        "",
        "2. **Runtime (host) snapshot** — one pass collects lightweight host facts used for context. "
        f"This run recorded **{listen_n}** listening endpoints (source: `{listen_src}`), "
        f"**{svc_n}** enabled systemd services (sample in JSON), "
        f"a bounded **auth/journal excerpt** (heuristic failed-login hints: **{auth_hints}**), "
        f"a bounded **security journal** excerpt (err..alert), and **pending apt upgrades** "
        f"(simulated count: **{pending}**; `None` if apt is unavailable). "
        "Full fields and excerpts are at the end of this document.",
        "",
        "3. **Correlation** — explicit rules may attach *runtime evidence* to specific findings and "
        "adjust priority with a human-readable reason. If no rule matches a finding, that finding still "
        "uses the global snapshot for context but may show **no per-finding runtime lines**.",
        "",
    ]
    if notes:
        lines.extend(
            [
                "**Runtime collection notes:**",
                "",
                *[f"- {n}" for n in notes],
                "",
            ]
        )
    lines.extend(
        [
            "## Findings",
            "",
        ]
    )
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
        if cf.correlation_notes:
            lines.append("**Correlation notes:**")
            lines.append("")
            for note in cf.correlation_notes:
                lines.append(f"- {note}")
            lines.append("")
        if s.evidence:
            lines.append("**Static evidence:**")
            lines.append("")
            for ev in s.evidence:
                lines.append(f"- `{ev.label}`: {ev.detail}")
            lines.append("")
        lines.append("**Runtime & correlation (this finding):**")
        lines.append("")
        if cf.runtime_evidence:
            for ev in cf.runtime_evidence:
                lines.append(f"- `{ev.label}`: {ev.detail}")
        else:
            lines.append(
                "- *No runtime lines were attached by correlation rules for this control.* "
                "The host-wide snapshot still applies for manual interpretation (see § Runtime snapshot)."
            )
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
