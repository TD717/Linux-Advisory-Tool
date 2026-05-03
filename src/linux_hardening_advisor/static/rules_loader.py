"""Load ``BenchmarkRule`` objects from YAML files."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

import yaml

from linux_hardening_advisor.models.rules import BenchmarkRule

logger = logging.getLogger(__name__)


def load_rules_from_file(path: Path) -> list[BenchmarkRule]:
    """Load rules from a single ``.yaml``/``.yml``/``.json`` file."""
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() == ".json":
        data = json.loads(text)
    else:
        data = yaml.safe_load(text)
    if data is None:
        return []
    if not isinstance(data, list):
        raise ValueError(f"{path}: root must be a list of rule objects")
    rules: list[BenchmarkRule] = []
    for item in data:
        if not isinstance(item, dict):
            raise ValueError(f"{path}: each rule must be a mapping")
        rules.append(BenchmarkRule.from_mapping(item))
    logger.info("Loaded %d rules from %s", len(rules), path)
    return rules


def _collect_rule_paths(directory: Path, *, recursive: bool) -> list[Path]:
    """Return sorted rule file paths from a directory tree."""
    if not directory.is_dir():
        raise FileNotFoundError(str(directory))
    glober = directory.rglob if recursive else directory.glob
    paths: set[Path] = set()
    for pat in ("*.yaml", "*.yml", "*.json"):
        paths.update(glober(pat))
    return sorted(paths)


def load_rules_from_directory(directory: Path, *, recursive: bool = True) -> list[BenchmarkRule]:
    """
    Load and merge all ``*.yaml`` / ``*.yml`` / ``*.json`` rule files.

    """
    paths = _collect_rule_paths(directory, recursive=recursive)
    rules: list[BenchmarkRule] = []
    for p in paths:
        rules.extend(load_rules_from_file(p))
    return rules


def iter_rule_files(directory: Path, *, recursive: bool = True) -> Iterator[Path]:
    """Yield rule file paths for ``advisory list-benchmarks``."""
    if not directory.is_dir():
        return
    yield from _collect_rule_paths(directory, recursive=recursive)
