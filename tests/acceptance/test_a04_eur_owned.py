"""A04: EUR-owned replacement list; no baseline configured -> V06 UNKNOWN per file, and
install-gate BLOCKS on that UNKNOWN. With a baseline but missing original / restoration,
each failure is reported separately."""

from __future__ import annotations

from pathlib import Path

import pytest

from gso_checker import compare, gate
from gso_checker.config import load_config, load_rules
from gso_checker.model import GateOutcome, Verdict
from gso_checker.store import Store
from tests.helpers import (MOD, OVERLAY_ZIP, PROFILE, REL_054E, build_world, load_world,
                           probe_not_running, require, write_config, write_zip, EUR_CFG, GSO_CFG,
                           GSO_MAIN, CORE_NEW, EUR_MAIN)


@pytest.mark.real
def test_a04_real_054e_unknown_per_eur_file(tmp_path: Path) -> None:
    require(OVERLAY_ZIP, REL_054E)
    cfg_path = write_config(
        tmp_path / "checker.toml", data_dir=tmp_path / "data", game_root=tmp_path / "no_game",
        overlay=OVERLAY_ZIP, overlay_prefix="overlay/", baseline=None, backups=None,
        not_installed=("README.txt", "SHARED.txt"),
        releases=[{"id": "0.5.4e", "path": REL_054E.as_posix(), "profile": PROFILE,
                   "packaging": "full", "packaging_root": "mod-parent"}])
    cfg = load_config(cfg_path)
    rules = load_rules(cfg.rules_path)
    store = Store(cfg.db_path)
    try:
        res = compare.run_version_checks(cfg, "0.5.4e", store, rules, include_live=False)
    finally:
        store.close()
    v06 = {f.normalized_path: f for f in res.findings if f.rule_id == "V06"}
    for p in ("script/main.nut", "TATW.cfg", "data/export_descr_unit.txt", "data/text/menu_english.txt"):
        assert p in v06, p
        assert v06[p].result is Verdict.UNKNOWN
        assert "EUR baseline not configured" in v06[p].message
    assert not [p for p in v06 if p.startswith(("script/eur40/", "GSO/"))]
    assert all(f.result is not Verdict.PASS for f in v06.values())


def test_a04_gate_blocks_on_v06_unknown(tmp_path: Path) -> None:
    w = build_world(tmp_path, baseline=False)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_not_running, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.REFUSE
    checks = {c.name: c for c in d.checks}
    assert [c.name for c in d.checks] == list(gate.CHECK_ORDER)
    assert checks["backup"].verdict is Verdict.UNKNOWN
    assert "V06" in checks["backup"].reason and "TATW.cfg" in checks["backup"].reason
    assert checks["profile"].verdict is Verdict.UNKNOWN


def test_a04_each_failure_separately(tmp_path: Path) -> None:
    """Baseline present, no checker backup, both originals shipped under GSO/originals, uninstall
    script lacks the TATW.cfg restore: TATW.cfg fails on restoration only (its original is kept
    by the release), script/main.nut passes."""
    w = build_world(tmp_path, backup=False)
    m = MOD + "/"
    bat = b"@echo off\r\ncopy /Y \"GSO\\originals\\script\\main.nut\" \"script\\main.nut\" >nul\r\n"
    write_zip(w.good_zip, [(m + "TATW.cfg", GSO_CFG), (m + "script/main.nut", GSO_MAIN),
                           (m + "script/eur40/eur40Core.nut", CORE_NEW),
                           (m + "GSO/originals/TATW.cfg", EUR_CFG),
                           (m + "GSO/originals/script/main.nut", EUR_MAIN), (m + "GSO_Uninstall.bat", bat)])
    cfg, rules, store = load_world(w)
    try:
        res = compare.run_version_checks(cfg, "R-good", store, rules, include_live=False)
    finally:
        store.close()
    v06 = {f.normalized_path: f for f in res.findings if f.rule_id == "V06"}
    tatw, main = v06["TATW.cfg"], v06["script/main.nut"]
    assert tatw.result is Verdict.FAIL
    assert "original not saved" not in tatw.message
    assert "uninstall does not restore original" in tatw.message
    assert main.result is Verdict.PASS
    assert len([f for f in v06.values() if f.result is Verdict.FAIL]) == 1
