# gso-checker

Offline, evidence-based checker for GSO (Grand Strategy Overhaul) releases on
Divide and Conquer EUR / EUREX 1.5 with M2EX. Phase 1: release integrity (V01-V07),
install gate, confirmed install/uninstall, verification memory and review sheets.
No network, no AI, never launches or kills the game.

Status: skeleton. Modules are stubs; the tests in `tests/` define the behaviour.

## Quick start

1. Copy `checker.example.toml` to `checker.toml` and edit the paths
   (`checker.toml` is git-ignored).
2. Run from any folder:

```
C:\Python314\python.exe -m gso_checker --config checker.toml sources
C:\Python314\python.exe -m gso_checker --config checker.toml compare --release 0.5.4e
C:\Python314\python.exe -m gso_checker --config checker.toml check --release 0.5.4e
C:\Python314\python.exe -m gso_checker --config checker.toml install-gate --release 0.5.4e
C:\Python314\python.exe -m gso_checker --config checker.toml install --release 0.5.4e
C:\Python314\python.exe -m gso_checker --config checker.toml uninstall --install <ID>
C:\Python314\python.exe -m gso_checker --config checker.toml sheet export --release 0.5.4e
C:\Python314\python.exe -m gso_checker --config checker.toml sheet import --file review_0.5.4e.csv
```

Exit codes: 0 PASS/ALLOW, 1 FAIL, 2 UNKNOWN, 3 usage error or blocked.
Reports (`.txt` + `.json`) go to `<data_dir>/reports/`.

## Tests

```
C:\Python314\python.exe -m pytest -q
```

Tests marked `real` read the corpus on E: (read-only) and skip when it is missing.

See ARCHITECTURE.md for the module contracts and CLAUDE.md for project rules.
