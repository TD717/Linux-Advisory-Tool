"""Static rule evaluation tests (mocked commands)."""

from unittest.mock import patch

from linux_hardening_advisor.collectors.subprocess_runner import CommandResult
from linux_hardening_advisor.models.rules import BenchmarkRule, CheckType, FindingCondition
from linux_hardening_advisor.static.evaluator import evaluate_rule


def _cmd_rule(contains: bool) -> BenchmarkRule:
    return BenchmarkRule(
        id="T-CMD",
        section="test",
        title="test command",
        category="test",
        rationale="r",
        check_type=CheckType.COMMAND_OUTPUT_CONTAINS
        if contains
        else CheckType.COMMAND_OUTPUT_NOT_CONTAINS,
        target={},
        expected={"substring": "BAD"},
        finding_condition=FindingCondition.NON_COMPLIANT_IF_TRUE,
        recommendation="rec",
        severity="low",
        tags=(),
        verification_command="true",
    )


@patch("linux_hardening_advisor.static.evaluator.run_shell")
def test_command_output_contains_non_compliant(mock_shell):
    mock_shell.return_value = CommandResult(None, "x", "line BAD\n", "", 0)
    f = evaluate_rule(_cmd_rule(contains=True))
    assert f.status.value == "non_compliant"


@patch("linux_hardening_advisor.static.evaluator.run_shell")
def test_command_output_contains_compliant(mock_shell):
    mock_shell.return_value = CommandResult(None, "x", "ok\n", "", 0)
    f = evaluate_rule(_cmd_rule(contains=True))
    assert f.status.value == "compliant"


@patch("linux_hardening_advisor.static.evaluator.run_shell")
def test_command_output_not_contains(mock_shell):
    rule = BenchmarkRule(
        id="T-NOT",
        section="test",
        title="test",
        category="test",
        rationale="r",
        check_type=CheckType.COMMAND_OUTPUT_NOT_CONTAINS,
        target={},
        expected={"substring": "FORBIDDEN"},
        finding_condition=FindingCondition.NON_COMPLIANT_IF_TRUE,
        recommendation="r",
        severity="low",
        tags=(),
        verification_command="true",
    )
    mock_shell.return_value = CommandResult(None, "x", "FORBIDDEN", "", 0)
    f = evaluate_rule(rule)
    assert f.status.value == "non_compliant"
