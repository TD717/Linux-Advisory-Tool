"""Command-line interface (argparse, stdlib-only)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Callable

from linux_hardening_advisor.engine import run_scan
from linux_hardening_advisor.reporting import print_terminal_summary, report_to_json, report_to_markdown
from linux_hardening_advisor.runtime.host_snapshot import collect_full_snapshot
from linux_hardening_advisor.static.rules_loader import iter_rule_files, load_rules_from_directory

_LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"


def _default_rules_dir() -> Path:
    """Project ``rules/`` tree (loads ``cis/``, ``examples/``, etc. recursively)."""
    return Path(__file__).resolve().parents[2] / "rules"


def _run_advisory(rules_dir: Path, *, skip_runtime: bool, json_out: Path | None, markdown_out: Path | None) -> int:
    report = run_scan(rules_dir, skip_runtime=skip_runtime)
    print_terminal_summary(report)
    if json_out:
        json_out.write_text(report_to_json(report), encoding="utf-8")
        logging.info("Wrote JSON report to %s", json_out)
    if markdown_out:
        markdown_out.write_text(report_to_markdown(report), encoding="utf-8")
        logging.info("Wrote Markdown report to %s", markdown_out)
    return 0


def _list_benchmarks(rules_dir: Path) -> int:
    if not rules_dir.is_dir():
        print(f"Rules directory not found: {rules_dir}", file=sys.stderr)
        return 2
    for f in iter_rule_files(rules_dir):
        print(f)
    n = len(load_rules_from_directory(rules_dir))
    print(f"Total rules loaded: {n}")
    return 0


def _show_host_snapshot() -> int:
    snap = collect_full_snapshot()
    print(json.dumps(snap.to_summary(), indent=2))
    return 0


def _prompt_path(prompt: str) -> Path | None:
    raw = input(prompt).strip()
    if not raw:
        return None
    return Path(raw)


def _interactive_menu(rules_dir: Path) -> int:
    actions: dict[str, tuple[str, Callable[[], int]]] = {
        "1": ("Run full advisory", lambda: _run_advisory(rules_dir, skip_runtime=False, json_out=None, markdown_out=None)),
        "2": (
            "Run full advisory (skip runtime)",
            lambda: _run_advisory(rules_dir, skip_runtime=True, json_out=None, markdown_out=None),
        ),
        "3": (
            "Run full advisory and write JSON report",
            lambda: _run_advisory(
                rules_dir,
                skip_runtime=False,
                json_out=_prompt_path("JSON output path (default: advisory-report.json): ") or Path("advisory-report.json"),
                markdown_out=None,
            ),
        ),
        "4": (
            "Run full advisory and write Markdown report",
            lambda: _run_advisory(
                rules_dir,
                skip_runtime=False,
                json_out=None,
                markdown_out=_prompt_path("Markdown output path (default: advisory-report.md): ")
                or Path("advisory-report.md"),
            ),
        ),
        "5": (
            "Run full advisory and write JSON + Markdown reports",
            lambda: _run_advisory(
                rules_dir,
                skip_runtime=False,
                json_out=_prompt_path("JSON output path (default: advisory-report.json): ") or Path("advisory-report.json"),
                markdown_out=_prompt_path("Markdown output path (default: advisory-report.md): ")
                or Path("advisory-report.md"),
            ),
        ),
        "6": ("List benchmark rule files", lambda: _list_benchmarks(rules_dir)),
        "7": ("Show host runtime snapshot", _show_host_snapshot),
    }

    while True:
        print("\nLinux Hardening Advisor Menu")
        print(f"Rules directory: {rules_dir}")
        for key, (label, _) in actions.items():
            print(f"{key}. {label}")
        print("0. Exit")
        choice = input("Select an option: ").strip()
        if choice == "0":
            print("Exiting.")
            return 0
        action = actions.get(choice)
        if action is None:
            print("Invalid option. Please choose a number from the menu.")
            continue
        try:
            print("")
            rc = action[1]()
            if rc != 0:
                print(f"Command finished with status {rc}.")
        except KeyboardInterrupt:
            print("\nOperation interrupted.")
        except Exception as exc:  # noqa: BLE001
            logging.exception("Menu action failed: %s", exc)
            print(f"Error: {exc}")


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

    parser.add_argument(
        "--menu",
        action="store_true",
        help="Launch interactive numbered menu (default when no command is provided)",
    )

    sub = parser.add_subparsers(dest="command")

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
    if args.menu or args.command is None:
        return _interactive_menu(rules_dir)

    if args.command == "run":
        return _run_advisory(
            rules_dir,
            skip_runtime=args.skip_runtime,
            json_out=args.json_out,
            markdown_out=args.markdown_out,
        )

    if args.command == "list-benchmarks":
        return _list_benchmarks(rules_dir)

    if args.command == "host-snapshot":
        return _show_host_snapshot()

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
