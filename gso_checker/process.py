"""Read-only game-process observation. Never launches, signals or kills anything.

Contract: ARCHITECTURE.md 4.9. subprocess is used ONLY here, ONLY with the
commands in ALLOWED_COMMANDS.
"""

from __future__ import annotations

import logging
from typing import Callable, Protocol, Sequence

from gso_checker.model import ProcessInfo, ProcessObservation

logger = logging.getLogger(__name__)

# argv[0] values the runner may execute. Nothing else.
ALLOWED_COMMANDS: tuple[str, ...] = ("tasklist", "powershell", "wmic")

TASKLIST_ARGV: tuple[str, ...] = ("tasklist", "/FO", "CSV")
POWERSHELL_ARGV_PREFIX: tuple[str, ...] = (
    "powershell", "-NoProfile", "-NonInteractive", "-Command",
)
# Followed by: "Get-Process -Id <pid>[,<pid>...] | Select-Object Id,Path | ConvertTo-Csv -NoTypeInformation"
WMIC_ARGV_PREFIX: tuple[str, ...] = ("wmic", "process", "where")
# Followed by: "ProcessId=<pid>", "get", "ProcessId,ExecutablePath", "/format:csv"

Runner = Callable[[Sequence[str]], str]
"""Runs argv (argv[0] in ALLOWED_COMMANDS), returns decoded stdout, raises
OSError / subprocess.CalledProcessError / subprocess.TimeoutExpired on failure."""


class ProcessProbe(Protocol):
    def __call__(self, names: Sequence[str]) -> ProcessObservation: ...


def parse_tasklist_csv(text: str) -> list[ProcessInfo]:
    """Parse `tasklist /FO CSV` output (header row 'Image Name','PID',...).
    path is None. Raises ValueError when the header is missing or a PID is not
    an integer (caller turns that into state UNKNOWN)."""
    raise NotImplementedError


def parse_powershell_paths_csv(text: str) -> dict[int, str]:
    """Parse `... | Select-Object Id,Path | ConvertTo-Csv -NoTypeInformation`
    output: header '"Id","Path"'. Empty Path values are omitted."""
    raise NotImplementedError


def parse_wmic_csv(text: str) -> dict[int, str]:
    """Parse `wmic process ... get ProcessId,ExecutablePath /format:csv` output:
    blank lines ignored, header 'Node,ExecutablePath,ProcessId'."""
    raise NotImplementedError


def default_runner(argv: Sequence[str]) -> str:
    """subprocess.run(list(argv), capture_output=True, text=True, timeout=15,
    check=True, creationflags=CREATE_NO_WINDOW on Windows). Raises ValueError
    when argv[0] is not in ALLOWED_COMMANDS."""
    raise NotImplementedError


def observe(names: Sequence[str], *, runner: Runner | None = None) -> ProcessObservation:
    """Observe whether any process whose image name matches one of `names`
    (case-insensitive) is alive.

    1. runner(TASKLIST_ARGV); failure or ValueError while parsing -> UNKNOWN
       with detail naming the error (never NOT_RUNNING).
    2. No match -> NOT_RUNNING, method 'tasklist'.
    3. Matches -> RUNNING; paths filled from PowerShell (method
       'tasklist+powershell'), falling back to wmic ('tasklist+wmic'); if both
       fail the processes keep path None and detail says 'path unavailable'.
    observed_at_utc = model.utc_iso(model._utcnow()).
    """
    raise NotImplementedError


class SystemProcessProbe:
    """Default probe used by the CLI: observe(names) with default_runner."""

    def __call__(self, names: Sequence[str]) -> ProcessObservation:
        raise NotImplementedError
