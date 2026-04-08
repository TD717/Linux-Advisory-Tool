"""Command-line interface (argparse, stdlib-only)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

from linux_hardening_advisor.engine import run_scan
from linux_hardening_advisor.reporting import print_terminal_summary, report_to_json, report_to_markdown
from linux_hardening_advisor.runtime.listening_ports import collect_listening_ports
from linux_hardening_advisor.static.rules_loader import iter_rule_files, load_rules_from_directory

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _default_rules_dir() -> Path:
    """Project ``rules/`` tree (loads ``cis/``, ``examples/``, etc. recursively)."""
    return Path(__file__).resolve().parents[2] / "rules"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="advisory",
        description=(
            "Linux Hardening Advisor — static benchmark checks, lightweight host "
            "snapshot, and explainable advisory reports (not automatic remediation)."
        ),
    )
    parser.add_argument(
        "--rules-dir",
        type=Path,
        default=_default_rules_dir(),
        help="Root directory of YAML/JSON benchmark rules (default: ./rules; loads subfolders recursively)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")

    sub = parser.add_subparsers(dest="command", required=True)

    p_run = sub.add_parser(
        "run",
        help="Run full advisory: benchmark checks, host snapshot, correlation, summary",
        description=(
            "Evaluates YAML/JSON rules under --rules-dir, merges runtime context (e.g. listening sockets), "
            "applies correlation, prints a summary. Use --json-out / --markdown-out for report files."
        ),
    )
    p_run.add_argument("--json-out", type=Path, help="Write structured JSON advisory report")
    p_run.add_argument("--markdown-out", type=Path, help="Write Markdown advisory report")
    p_run.add_argument(
        "--skip-runtime",
        action="store_true",
        help="Skip runtime collectors (benchmark-only; no host snapshot for correlation)",
    )

    sub.add_parser(
        "list-benchmarks",
        help="List benchmark rule files under --rules-dir and how many rules load",
    )

    sub.add_parser(
        "host-snapshot",
        help="Print current host snapshot as JSON (e.g. listening sockets; expands later)",
    )

    args = parser.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format=_LOG_FORMAT)

    rules_dir: Path = args.rules_dir
    if args.command == "run":
        report = run_scan(rules_dir, skip_runtime=args.skip_runtime)
        print_terminal_summary(report)
        if args.json_out:
            args.json_out.write_text(report_to_json(report), encoding="utf-8")
            logging.info("Wrote JSON report to %s", args.json_out)
        if args.markdown_out:
            args.markdown_out.write_text(report_to_markdown(report), encoding="utf-8")
            logging.info("Wrote Markdown report to %s", args.markdown_out)
        return 0

    if args.command == "list-benchmarks":
        if not rules_dir.is_dir():
            print(f"Rules directory not found: {rules_dir}", file=sys.stderr)
            return 2
        for f in iter_rule_files(rules_dir):
            print(f)
        n = len(load_rules_from_directory(rules_dir))
        print(f"Total rules loaded: {n}")
        return 0

    if args.command == "host-snapshot":
        snap = collect_listening_ports()
        print(json.dumps(snap.to_summary(), indent=2))
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
