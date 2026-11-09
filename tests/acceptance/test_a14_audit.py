"""A14: source audit (no network, no AI, no game launch/kill, subprocess confined to the
process probe) and dynamic proof that check/compare/sources/install-gate/sheet never write
under the configured game root."""

from __future__ import annotations

import ast
import io
from pathlib import Path

from gso_checker import cli
from tests.helpers import (PROJECT_ROOT, build_world, make_read_only, make_writable, probe_not_running,
                           snapshot_tree)

PKG = PROJECT_ROOT / "gso_checker"
FORBIDDEN_MODULES = {"urllib", "urllib3", "requests", "httpx", "aiohttp", "socket", "http", "ftplib",
                     "smtplib", "telnetlib", "xmlrpc", "webbrowser", "ssl", "anthropic", "openai",
                     "ctypes", "multiprocessing"}
FORBIDDEN_CALLS = {"os.startfile", "os.system", "os.popen", "os.kill", "os.execv", "os.execl",
                   "os.spawnl", "os.spawnv", "signal.signal"}
FORBIDDEN_TEXT = ("taskkill", "Stop-Process", "ShellExecute", "steam://", "http://", "https://")


def _modules() -> dict[str, ast.Module]:
    return {p.name: ast.parse(p.read_text(encoding="utf-8"), filename=str(p)) for p in PKG.glob("*.py")}


def _imports(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def _dotted_calls(tree: ast.Module) -> set[str]:
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            out.add(f"{node.func.value.id}.{node.func.attr}")
    return out


def test_a14_no_network_ai_or_launch_code() -> None:
    mods = _modules()
    expected = {"__init__.py", "__main__.py", "cli.py", "compare.py", "config.py", "gate.py", "hashing.py",
                "history.py", "installer.py", "manifest.py", "memory.py", "model.py", "process.py",
                "report.py", "sheet.py", "store.py"}
    assert expected <= set(mods), sorted(expected - set(mods))
    for name, tree in mods.items():
        assert not (_imports(tree) & FORBIDDEN_MODULES), (name, _imports(tree) & FORBIDDEN_MODULES)
        assert not (_dotted_calls(tree) & FORBIDDEN_CALLS), (name, _dotted_calls(tree) & FORBIDDEN_CALLS)
        text = (PKG / name).read_text(encoding="utf-8")
        for bad in FORBIDDEN_TEXT:
            assert bad not in text, (name, bad)
        assert text.isascii(), name


def test_a14_subprocess_confined_to_process_probe() -> None:
    mods = _modules()
    users = sorted(n for n, t in mods.items() if "subprocess" in _imports(t))
    assert users == ["process.py"]
    from gso_checker import process
    assert process.ALLOWED_COMMANDS == ("tasklist", "powershell", "wmic")
    text = (PKG / "process.py").read_text(encoding="utf-8")
    assert "shell=True" not in text


def test_a14_read_only_commands_never_write_game_root(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    make_read_only(w.game_root)
    try:
        before = snapshot_tree(w.game_root)
        cmds = [
            ["sources"],
            ["compare", "--release", "R-good"],
            ["check", "--release", "R-stale"],
            ["install-gate", "--release", "R-good"],
            ["sheet", "export", "--release", "R-stale"],
        ]
        for argv in cmds:
            out = io.StringIO()
            code = cli.main(["--config", str(w.config), *argv], probe=probe_not_running, stdout=out)
            assert code in (0, 1, 2, 3), argv
            assert out.getvalue().startswith("GSO CHECKER | profile: EUREX-1.5"), argv
        exported = sorted((w.data_dir / "reports").glob("review_R-stale.csv"))
        assert exported, "sheet export must write into the checker data dir"
        out = io.StringIO()
        cli.main(["--config", str(w.config), "sheet", "import", "--file", str(exported[0])],
                 probe=probe_not_running, stdout=out)
        assert snapshot_tree(w.game_root) == before
        assert len(list((w.data_dir / "reports").glob("*.txt"))) >= len(cmds) + 1
    finally:
        make_writable(w.game_root)
