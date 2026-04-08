"""Structured advisory reports (terminal, JSON, Markdown)."""

from linux_hardening_advisor.reporting.json_report import report_to_json
from linux_hardening_advisor.reporting.markdown_report import report_to_markdown
from linux_hardening_advisor.reporting.terminal import print_terminal_summary

__all__ = ["print_terminal_summary", "report_to_json", "report_to_markdown"]
