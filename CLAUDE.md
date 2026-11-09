# gso-checker - project rules

Offline checker for GSO releases (spec v0.2, phase 1). Read ARCHITECTURE.md before
touching code; its interfaces are binding. Tests are the acceptance contract: make them
pass, do not weaken them.

## Runtime
- Python: `C:\Python314\python.exe` (always the full path). Tests: `C:\Python314\python.exe -m pytest -q`.
- Standard library only: sqlite3, zipfile, hashlib, tomllib, csv, json, argparse, logging,
  dataclasses, pathlib. `subprocess` ONLY in process.py for process listing
  (tasklist / powershell Get-Process / wmic) and, in phase 2, the repo's own gate commands.
- XLSX export only if `openpyxl` is importable; otherwise CSV only and say so
  (`sheet.XLSX_UNAVAILABLE_NOTE`). Never install packages without the user's permission.

## Code rules
- ASCII-only output (console, reports, source files).
- No bare `except:`; catch specific exceptions (or `Exception` with logging).
- Type hints on every def. `logger = logging.getLogger(__name__)`; no `print` except the
  CLI's final report writer (`report.emit`).
- Timestamps UTC via `model._utcnow()` only; never `datetime.utcnow()`.

## Safety (non-negotiable)
- NEVER write under the configured `game_root` except inside confirmed `install` /
  `uninstall` (exact typed id, gate ALLOW / game not running). `sources`, `compare`,
  `check`, `install-gate`, `sheet` are read-only toward the game.
- Never launch, signal or kill the game. No network, no AI calls.
- Tests never write to `D:\` or `E:\`: use `tmp_path`. Real-file tests only READ E:/D:
  and `pytest.skip` cleanly when a path is missing (`tests/helpers.require`).
- Live game folder `D:\SteamLibrary\steamapps\common\Medieval II Total War\mods\Divide_and_Conquer_EUR`
  is read-only for everyone working on this repo.

## Repo
- Private, local only: never push, never add a remote, no secrets.
- `.gitignore` covers `*.db`, `reports/`, `checker.toml` (ship `checker.example.toml`).
- Real corpus: `E:\GSO_checker_addendum_A\` (see fixtures/README.txt). Profile under test: `EUREX-1.5`.
  EUR baseline is MISSING for now: V06 must be UNKNOWN (never PASS) and install-gate must block.

## Role (2026-11-08)
This tool is the referee for GSO releases. It is driven by `release.bat` in Desktop\Projects\eur40-nb-int (see that repo's CLAUDE.md and `/gso-release` skill). Never install from here without the gate's ALLOW and BB1's typed release id.
