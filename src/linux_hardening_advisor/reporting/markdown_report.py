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
        "Auth and security journal excerpts appear as readable blocks under **Runtime snapshot (summary)** below "
        "(not only inside the JSON).",
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
                if pa.supporting_evidence:
                    for se in pa.supporting_evidence:
                        lines.append(f"  - `{se.label}`: {se.detail}")
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
                "- *No per-finding correlation attachment for this control.* "
                "Correlation only adds extra runtime lines when an explicit hybrid rule matches "
                "(e.g. SSH-related non-compliance with TCP/22 exposed, firewall issues with many listeners, "
                "or high failed-login hints in the captured auth excerpt). "
                "Runtime data for the whole host is still collected once per scan — see **Runtime snapshot (summary)** below."
            )
        lines.append("")
        lines.append("---")
        lines.append("")
    lines.append("## Runtime snapshot (summary)")
    lines.append("")
    auth_prev = snap.get("auth_log_excerpt_preview") or ""
    sec_prev = snap.get("security_journal_excerpt_preview") or ""
    lines.append("### Authentication failure indicators (heuristic)")
    lines.append("")
    lines.append(
        f"- **Heuristic failed-login hint count** (pattern matches in the captured auth excerpt): "
        f"**{auth_hints}**"
    )
    lines.append("")
    lines.append("### Authentication-related log excerpt")
    lines.append("")
    if auth_prev.strip():
        lines.append("```")
        lines.append(auth_prev.rstrip())
        lines.append("```")
    else:
        lines.append(
            "*No authentication excerpt was collected* (empty journal/auth.log, insufficient permissions, "
            "or SSH units had no recent lines in the bounded window)."
        )
    lines.append("")
    lines.append("### Security-relevant journal events (err..alert)")
    lines.append("")
    if sec_prev.strip():
        lines.append("```")
        lines.append(sec_prev.rstrip())
        lines.append("```")
    else:
        lines.append(
            "*No err..alert journal excerpt was collected* (empty result, or `journalctl` failed — see "
            "collection notes above if any)."
        )
    lines.append("")
    lines.append("### Full snapshot (machine-readable JSON)")
    lines.append("")
    lines.append("```json")
    lines.append(__import__("json").dumps(dict(report.runtime_snapshot_summary), indent=2))
    lines.append("```")
    lines.append("")
    return "\n".join(lines)
