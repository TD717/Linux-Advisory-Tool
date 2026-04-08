"""JSON serialization for ``ScanReport``."""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime
from typing import Any

from linux_hardening_advisor.models.findings import ScanReport


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, dict):
        return {k: _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(x) for x in obj]
    if hasattr(obj, "value"):  # Enum
        return getattr(obj, "value", obj)
    return obj


def report_to_json(report: ScanReport, *, indent: int = 2) -> str:
    """Serialize a scan report to pretty-printed JSON."""
    payload = {
        "generated_at": report.generated_at.isoformat(),
        "hostname": report.hostname,
        "runtime_snapshot_summary": dict(report.runtime_snapshot_summary),
        "correlated_findings": [],
    }
    for cf in report.correlated_findings:
        payload["correlated_findings"].append(
            {
                "priority": cf.priority,
                "correlation_notes": list(cf.correlation_notes),
                "priority_adjustments": [
                    {
                        "reason": pa.reason,
                        "delta": pa.delta,
                        "supporting_evidence": [asdict(e) for e in pa.supporting_evidence],
                    }
                    for pa in cf.priority_adjustments
                ],
                "runtime_evidence": [asdict(e) for e in cf.runtime_evidence],
                "static": _static_as_dict(cf.static),
            }
        )
    return json.dumps(_json_safe(payload), indent=indent, ensure_ascii=False)


def _static_as_dict(s: Any) -> dict[str, Any]:
    d = asdict(s)
    d["status"] = s.status.value
    d["evidence"] = [asdict(e) for e in s.evidence]
    return d
