"""Read-only game-process observation. Never launches, signals or kills anything.

Contract: ARCHITECTURE.md 4.9. subprocess is used ONLY here, ONLY with the
commands in ALLOWED_COMMANDS.
"""

from __future__ import annotations

import csv
import io
import logging
import subprocess
import sys
from typing import Callable, Protocol, Sequence

from gso_checker import model
from gso_checker.model import ProcessInfo, ProcessObservation, ProcessState

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

_RUN_ERRORS = (OSError, subprocess.SubprocessError, ValueError)


class ProcessProbe(Protocol):
    def __call__(self, names: Sequence[str]) -> ProcessObservation: ...


def _rows(text: str) -> list[list[str]]:
    return [r for r in csv.reader(io.StringIO(text.lstrip("\ufeff"))) if r and any(c.strip() for c in r)]


def parse_tasklist_csv(text: str) -> list[ProcessInfo]:
    """Parse `tasklist /FO CSV` output (header row 'Image Name','PID',...).
    path is None. Raises ValueError when the header is missing or a PID is not
    an integer (caller turns that into state UNKNOWN)."""
    rows = _rows(text)
    if not rows:
        raise ValueError("tasklist output is empty")
    header = [c.strip().casefold() for c in rows[0]]
    if "image name" not in header or "pid" not in header:
        raise ValueError(f"tasklist header missing: {rows[0][:3]!r}")
    i_name, i_pid = header.index("image name"), header.index("pid")
    out: list[ProcessInfo] = []
    for row in rows[1:]:
        if len(row) <= max(i_name, i_pid):
            raise ValueError(f"short tasklist row: {row!r}")
        try:
            pid = int(row[i_pid].strip())
        except ValueError as exc:
            raise ValueError(f"bad PID {row[i_pid]!r}") from exc
        out.append(ProcessInfo(image=row[i_name], pid=pid, path=None))
    return out


def _paths_by_header(rows: list[list[str]], id_col: str, path_col: str) -> dict[int, str]:
    header_idx = next((i for i, r in enumerate(rows)
                       if id_col in [c.strip().casefold() for c in r]
                       and path_col in [c.strip().casefold() for c in r]), None)
    if header_idx is None:
        raise ValueError(f"header with {id_col}/{path_col} not found")
    header = [c.strip().casefold() for c in rows[header_idx]]
    i_id, i_path = header.index(id_col), header.index(path_col)
    out: dict[int, str] = {}
    for row in rows[header_idx + 1:]:
        if len(row) <= max(i_id, i_path):
            continue
        value = row[i_path].strip()
        if not value:
            continue
        try:
            out[int(row[i_id].strip())] = value
        except ValueError as exc:
            raise ValueError(f"bad process id {row[i_id]!r}") from exc
    return out


def parse_powershell_paths_csv(text: str) -> dict[int, str]:
    """Parse `... | Select-Object Id,Path | ConvertTo-Csv -NoTypeInformation`
    output: header '"Id","Path"'. Empty Path values are omitted."""
    return _paths_by_header(_rows(text), "id", "path")


def parse_wmic_csv(text: str) -> dict[int, str]:
    """Parse `wmic process ... get ProcessId,ExecutablePath /format:csv` output:
    blank lines ignored, header 'Node,ExecutablePath,ProcessId'."""
    return _paths_by_header(_rows(text), "processid", "executablepath")


def default_runner(argv: Sequence[str]) -> str:
    """subprocess.run(list(argv), capture_output=True, text=True, timeout=15,
    check=True, creationflags=CREATE_NO_WINDOW on Windows). Raises ValueError
    when argv[0] is not in ALLOWED_COMMANDS."""
    args = list(argv)
    if not args or args[0] not in ALLOWED_COMMANDS:
        raise ValueError(f"command not allowed: {args[:1]!r}")
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    result = subprocess.run(args, capture_output=True, text=True, errors="replace", timeout=15,
                            check=True, creationflags=flags)
    return result.stdout


def _lookup_paths(pids: Sequence[int], run: Runner) -> tuple[dict[int, str], str, str]:
    """Return (paths, method suffix, error detail). Suffix '' when nothing worked."""
    ids = ",".join(str(p) for p in pids)
    ps_cmd = (f"Get-Process -Id {ids} | Select-Object Id,Path | "
              "ConvertTo-Csv -NoTypeInformation")
    errors: list[str] = []
    try:
        paths = parse_powershell_paths_csv(run(POWERSHELL_ARGV_PREFIX + (ps_cmd,)))
        return paths, "powershell", ""
    except _RUN_ERRORS as exc:
        errors.append(f"powershell: {exc}")
    merged: dict[int, str] = {}
    try:
        for pid in pids:
            argv = WMIC_ARGV_PREFIX + (f"ProcessId={pid}", "get", "ProcessId,ExecutablePath", "/format:csv")
            merged.update(parse_wmic_csv(run(argv)))
        return merged, "wmic", ""
    except _RUN_ERRORS as exc:
        errors.append(f"wmic: {exc}")
    return {}, "", "; ".join(errors)


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
    run: Runner = runner if runner is not None else default_runner
    now = model.utc_iso(model._utcnow())
    try:
        procs = parse_tasklist_csv(run(TASKLIST_ARGV))
    except _RUN_ERRORS as exc:
        logger.warning("process listing failed: %s", exc)
        return ProcessObservation(ProcessState.UNKNOWN, (), now, "tasklist",
                                  f"cannot determine: tasklist failed: {exc}")
    wanted = {n.casefold() for n in names}
    hits = [p for p in procs if p.image.casefold() in wanted]
    if not hits:
        return ProcessObservation(ProcessState.NOT_RUNNING, (), now, "tasklist", "")
    paths, suffix, err = _lookup_paths([p.pid for p in hits], run)
    method = "tasklist" + (f"+{suffix}" if suffix else "")
    detail = f"path unavailable ({err})" if not suffix else ""
    if suffix and any(p.pid not in paths for p in hits):
        detail = "path unavailable for some processes"
    found = tuple(ProcessInfo(p.image, p.pid, paths.get(p.pid)) for p in hits)
    return ProcessObservation(ProcessState.RUNNING, found, now, method, detail)


class SystemProcessProbe:
    """Default probe used by the CLI: observe(names) with default_runner."""

    def __call__(self, names: Sequence[str]) -> ProcessObservation:
        return observe(names, runner=default_runner)
