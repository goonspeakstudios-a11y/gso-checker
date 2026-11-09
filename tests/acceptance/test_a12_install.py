"""A12: stale required file -> REFUSE naming it; corrected zip + backup -> ALLOW; install with
typed confirmation into a TMP tree (never D:), hashes verified, install id recorded;
uninstall restores the original bytes."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from gso_checker import cli, gate, installer
from gso_checker.model import ConfirmationError, GateOutcome, Verdict
from tests.helpers import (CORE_NEW, CORE_PATH, EUR_CFG, EUR_MAIN, GSO_CFG, LIVE_GAME_ROOT, build_world,
                           content_snapshot, load_world, probe_not_running, sha, snapshot_tree)


def test_a12_stale_refuses_naming_file(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-stale", probe=probe_not_running, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.REFUSE
    man = next(c for c in d.checks if c.name == "manifest")
    assert man.verdict is Verdict.FAIL and CORE_PATH in man.reason


def test_a12_good_allows(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_not_running, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.ALLOW, [(c.name, c.verdict, c.reason) for c in d.checks]
    assert all(c.verdict is Verdict.PASS for c in d.checks)


def test_a12_install_then_uninstall_restores(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    assert not str(w.live).upper().startswith(str(LIVE_GAME_ROOT).upper())
    pre_live = content_snapshot(w.live)
    pre_game_outside_mod = {k: v for k, v in snapshot_tree(w.game_root).items() if not k.startswith("mods/")}
    cfg, rules, store = load_world(w)
    try:
        with pytest.raises(ConfirmationError):
            installer.install(cfg, "R-good", confirm="r-good", probe=probe_not_running, store=store, rules=rules)
        assert content_snapshot(w.live) == pre_live

        rec = installer.install(cfg, "R-good", confirm="R-good", probe=probe_not_running, store=store, rules=rules)
        assert rec.post_check is Verdict.PASS and rec.status == "installed" and rec.differing == ()
        assert store.get_install(rec.install_id) == rec
        assert (w.live / CORE_PATH).read_bytes() == CORE_NEW
        assert (w.live / "TATW.cfg").read_bytes() == GSO_CFG
        files = {f.normalized_path: f for f in rec.files}
        assert files["TATW.cfg"].pre_existed and files["TATW.cfg"].pre_sha256 == sha(EUR_CFG)
        assert not files[CORE_PATH].pre_existed
        assert files[CORE_PATH].sha256 == sha(CORE_NEW)
        # backup written before copying, outside the game folder, with an inventory
        inv = json.loads((Path(rec.backup_dir) / "inventory.json").read_text(encoding="utf-8"))
        assert {x["normalized_path"]: x["sha256"] for x in inv["files"]} == {
            "TATW.cfg": sha(EUR_CFG), "script/main.nut": sha(EUR_MAIN)}
        assert w.game_root not in Path(rec.backup_dir).parents
        # nothing outside the mod folder changed
        assert {k: v for k, v in snapshot_tree(w.game_root).items() if not k.startswith("mods/")} == pre_game_outside_mod

        with pytest.raises(ConfirmationError):
            installer.uninstall(cfg, rec.install_id, confirm="wrong", probe=probe_not_running, store=store)
        un = installer.uninstall(cfg, rec.install_id, confirm=rec.install_id, probe=probe_not_running, store=store)
        assert un.status == "uninstalled"
        assert content_snapshot(w.live) == pre_live
        assert store.get_install(rec.install_id).status == "uninstalled"
    finally:
        store.close()


def test_a12_cli_install_prompt(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    out = io.StringIO()
    code = cli.main(["--config", str(w.config), "install", "--release", "R-good"],
                    probe=probe_not_running, stdin=io.StringIO("R-good\n"), stdout=out)
    text = out.getvalue()
    assert code == cli.EXIT_PASS, text
    assert "Type the release id to confirm: " in text
    assert "install id: inst-" in text and "post-check: PASS" in text
    assert sha(CORE_NEW) in text


def test_a12_cli_install_wrong_confirmation_no_writes(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    before = snapshot_tree(w.game_root)
    code = cli.main(["--config", str(w.config), "install", "--release", "R-good"],
                    probe=probe_not_running, stdin=io.StringIO("yes\n"), stdout=io.StringIO())
    assert code == cli.EXIT_USAGE_OR_BLOCKED
    assert snapshot_tree(w.game_root) == before
