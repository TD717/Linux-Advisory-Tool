"""Host data collection helpers (subprocess, parsing)."""

""" CommandResult -> a data object representing command execution output 
    run_shell -> Runs a command through the shell, when we need shell commands (pipes, redirects, &&, globbing)
    run_argv -> Runs a command as an argument list (no shell parsing), for example "systemctl", "is-enabled", "ssh.service". Safer for most checks because it avoids shell injection/parsing quirks.
"""
from linux_hardening_advisor.collectors.subprocess_runner import CommandResult, run_shell, run_argv

__all__ = ["CommandResult", "run_shell", "run_argv"]
