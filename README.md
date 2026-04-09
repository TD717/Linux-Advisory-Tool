# Linux Hardening Advisor

Local advisory CLI for standalone Linux hosts: static benchmark-style checks plus lightweight runtime context, explainable correlation, and JSON/Markdown reports.

**Framework code** lives under `src/linux_hardening_advisor/`. **Your CIS/benchmark rules** go under `rules/` (see `rules/cis/` and optional `rules/examples/`).

## Install (development)

```bash
cd "Advisory Tool"
python -m venv .venv
source .venv/bin/activate  # Linux/macOS
pip install -e ".[dev]"
```

## Usage

The installed command is **`advisory`**. All actions are **single-level** subcommands (same pattern as `run`—no extra nesting):

| Command | Purpose |
|--------|---------|
| `advisory run` | Full advisory: evaluate rules, host snapshot, correlation, terminal summary; optional `--json-out` / `--markdown-out`. |
| `advisory list-benchmarks` | List benchmark rule files under `--rules-dir` and how many rules load. |
| `advisory host-snapshot` | Print host snapshot as JSON (listening sockets; more collectors later). |

```bash
advisory run --json-out report.json --markdown-out report.md
advisory list-benchmarks
advisory host-snapshot
```
