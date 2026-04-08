"""Safe subprocess execution for static checks and runtime collectors."""

from __future__ import annotations

import logging
import shlex
import subprocess
from dataclasses import dataclass
from typing import Sequence

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """Normalized subprocess result for evidence and tests."""

    argv: tuple[str, ...] | None
    shell_command: str | None
    stdout: str
    stderr: str
    returncode: int


def run_argv(
    argv: Sequence[str],
    *,
    timeout_s: float = 120.0,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run a command with arguments (no shell). Preferred for safety."""
    cmd = tuple(argv)
    logger.debug("run_argv: %s", cmd)
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired as exc:
        err = f"timeout after {timeout_s}s"
        logger.warning("%s: %s", cmd, err)
        return CommandResult(argv=cmd, shell_command=None, stdout="", stderr=err, returncode=124)
    except OSError as exc:
        logger.warning("%s: %s", cmd, exc)
        return CommandResult(argv=cmd, shell_command=None, stdout="", stderr=str(exc), returncode=126)
    out = proc.stdout or ""
    err = proc.stderr or ""
    return CommandResult(argv=cmd, shell_command=None, stdout=out, stderr=err, returncode=proc.returncode)


def run_shell(
    command: str,
    *,
    timeout_s: float = 120.0,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """
    Run a shell pipeline (``bash -lc``). Use only when benchmark verification requires pipes.

    The command string is logged at debug level; avoid embedding secrets.
    """
    logger.debug("run_shell: %s", command)
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        err = f"timeout after {timeout_s}s"
        logger.warning("run_shell: %s", err)
        return CommandResult(argv=None, shell_command=command, stdout="", stderr=err, returncode=124)
    except OSError as exc:
        logger.warning("run_shell: %s", exc)
        return CommandResult(argv=None, shell_command=command, stdout="", stderr=str(exc), returncode=126)
    out = proc.stdout or ""
    err = proc.stderr or ""
    return CommandResult(argv=None, shell_command=command, stdout=out, stderr=err, returncode=proc.returncode)


def format_command_for_evidence(result: CommandResult) -> str:
    """Human-readable command description for reports."""
    if result.argv is not None:
        return " ".join(shlex.quote(a) for a in result.argv)
    return result.shell_command or ""
