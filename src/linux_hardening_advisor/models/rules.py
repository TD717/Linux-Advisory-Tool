"""Benchmark-oriented rule definitions loaded from YAML/JSON."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class CheckType(str, Enum):
    """Supported static evaluation strategies (extend as you add CIS checks)."""

    PACKAGE_ABSENT = "package_absent"
    PACKAGE_PRESENT = "package_present"
    SERVICE_DISABLED = "service_disabled"
    SERVICE_ENABLED = "service_enabled"
    SERVICE_ACTIVE = "service_active"
    SERVICE_INACTIVE = "service_inactive"
    CONFIG_VALUE_EQUALS = "config_value_equals"
    CONFIG_VALUE_NOT_EQUALS = "config_value_not_equals"
    FILE_EXISTS = "file_exists"
    FILE_NOT_EXISTS = "file_not_exists"
    FILE_MODE = "file_mode"
    COMMAND_OUTPUT_CONTAINS = "command_output_contains"
    COMMAND_OUTPUT_NOT_CONTAINS = "command_output_not_contains"
    COMMAND_EXIT_STATUS = "command_exit_status"
    CUSTOM = "custom"


class FindingCondition(str, Enum):
    """How to interpret check output vs expected values."""

    NON_COMPLIANT_IF_TRUE = "non_compliant_if_true"
    NON_COMPLIANT_IF_FALSE = "non_compliant_if_false"


@dataclass(frozen=True)
class BenchmarkRule:
    """One CIS-style control; typically defined in YAML under ``rules/``."""

    id: str
    section: str
    title: str
    category: str
    rationale: str
    check_type: CheckType
    target: Mapping[str, Any]
    expected: Mapping[str, Any]
    finding_condition: FindingCondition
    recommendation: str
    severity: str
    tags: tuple[str, ...] = ()
    verification_command: str | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    @staticmethod
    def from_mapping(data: Mapping[str, Any]) -> "BenchmarkRule":
        """Build from a parsed YAML/JSON object."""
        ct = CheckType(str(data["check_type"]))
        fc = FindingCondition(str(data.get("finding_condition", FindingCondition.NON_COMPLIANT_IF_TRUE.value)))
        tags = data.get("tags") or []
        if not isinstance(tags, Sequence):
            raise ValueError(f"Rule {data.get('id')}: tags must be a list")
        target = data.get("target") or {}
        expected = data.get("expected") or {}
        if not isinstance(target, Mapping) or not isinstance(expected, Mapping):
            raise ValueError(f"Rule {data.get('id')}: target and expected must be mappings")
        return BenchmarkRule(
            id=str(data["id"]),
            section=str(data.get("section", "")),
            title=str(data["title"]),
            category=str(data.get("category", "general")),
            rationale=str(data.get("rationale", "")),
            check_type=ct,
            target=dict(target),
            expected=dict(expected),
            finding_condition=fc,
            recommendation=str(data.get("recommendation", "")),
            severity=str(data.get("severity", "medium")),
            tags=tuple(str(t) for t in tags),
            verification_command=data.get("verification_command"),
            extra={k: v for k, v in data.items() if k not in _RULE_RESERVED},
        )


_RULE_RESERVED = frozenset(
    {
        "id",
        "section",
        "title",
        "category",
        "rationale",
        "check_type",
        "target",
        "expected",
        "finding_condition",
        "recommendation",
        "severity",
        "tags",
        "verification_command",
    }
)
