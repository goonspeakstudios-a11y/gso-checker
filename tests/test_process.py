"""Unit: process probe parsing with injected command output (no real processes touched)."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from gso_checker import process
from gso_checker.model import ProcessState

FIX = Path(__file__).resolve().parents[1] / "fixtures" / "synthetic" / "process"
TASKLIST = (FIX / "tasklist_running.csv").read_bytes().decode("ascii")
TASKLIST_NO_GAME = (FIX / "tasklist_no_game.csv").read_bytes().decode("ascii")
PS_CSV = (FIX / "powershell_paths.csv").read_bytes().decode("ascii")
WMIC_CSV = (FIX / "wmic_paths.csv").read_bytes().decode("ascii")
GAME_PATH = r"D:\SteamLibrary\steamapps\common\Medieval II Total War\M2EX.exe"


def test_parse_tasklist_csv() -> None:
    procs = process.parse_tasklist_csv(TASKLIST)
    assert [(p.image, p.pid) for p in procs] == [
        ("System Idle Process", 0), ("explorer.exe", 5120), ("M2EX.exe", 4242)]
    assert all(p.path is None for p in procs)


def test_parse_tasklist_garbage_raises() -> None:
    with pytest.raises(ValueError):
        process.parse_tasklist_csv("ERROR: Access denied.\r\n")


def test_parse_powershell_and_wmic() -> None:
    assert process.parse_powershell_paths_csv(PS_CSV) == {4242: GAME_PATH}
    assert process.parse_wmic_csv(WMIC_CSV) == {4242: GAME_PATH}


def fake_runner(outputs: dict[str, object]):
    calls: list[list[str]] = []

    def run(argv: Sequence[str]) -> str:
        calls.append(list(argv))
        out = outputs[argv[0]]
        if isinstance(out, Exception):
            raise out
        return str(out)
    return run, calls


def test_observe_running_with_powershell_path() -> None:
    run, calls = fake_runner({"tasklist": TASKLIST, "powershell": PS_CSV})
    o = process.observe(["m2ex.EXE"], runner=run)
    assert o.state is ProcessState.RUNNING
    assert [(p.pid, p.path) for p in o.processes] == [(4242, GAME_PATH)]
    assert o.method == "tasklist+powershell"
    assert o.observed_at_utc.endswith("Z")
    assert all(c[0] in process.ALLOWED_COMMANDS for c in calls)


def test_observe_running_falls_back_to_wmic() -> None:
    run, _ = fake_runner({"tasklist": TASKLIST, "powershell": OSError("blocked"), "wmic": WMIC_CSV})
    o = process.observe(["M2EX.exe"], runner=run)
    assert o.state is ProcessState.RUNNING and o.method == "tasklist+wmic"
    assert o.processes[0].path == GAME_PATH


def test_observe_running_without_path_is_still_running() -> None:
    run, _ = fake_runner({"tasklist": TASKLIST, "powershell": OSError("x"), "wmic": OSError("y")})
    o = process.observe(["M2EX.exe"], runner=run)
    assert o.state is ProcessState.RUNNING and o.processes[0].path is None
    assert "path unavailable" in o.detail


def test_observe_not_running() -> None:
    run, _ = fake_runner({"tasklist": TASKLIST_NO_GAME})
    o = process.observe(["M2EX.exe"], runner=run)
    assert o.state is ProcessState.NOT_RUNNING and o.processes == ()


@pytest.mark.parametrize("failure", [
    OSError("tasklist missing"),
    subprocess.CalledProcessError(1, ["tasklist"]),
    subprocess.TimeoutExpired(["tasklist"], 15),
    "INFO: garbage without header",
])
def test_observe_failure_is_unknown_never_not_running(failure: object) -> None:
    run, _ = fake_runner({"tasklist": failure})
    o = process.observe(["M2EX.exe"], runner=run)
    assert o.state is ProcessState.UNKNOWN
    assert o.detail


def test_default_runner_refuses_other_commands() -> None:
    with pytest.raises(ValueError):
        process.default_runner(["taskkill", "/IM", "M2EX.exe"])
