"""A02: historical A-B-A count on the real same-profile releases (expected value from
fixtures/expected/a02_historical_aba.json) and a synthetic 3-release A-B-A."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from gso_checker import compare, history, manifest
from gso_checker.config import load_config, load_rules
from gso_checker.model import Verdict
from gso_checker.store import Store
from tests.helpers import (MOD, PROFILE, PROJECT_ROOT, OVERLAY_ZIP, RELEASES_JSON, real_releases, require,
                           write_config, write_tree, write_zip)

EXPECTED = json.loads((PROJECT_ROOT / "fixtures" / "expected" / "a02_historical_aba.json").read_text(encoding="utf-8"))


@pytest.mark.real
def test_a02_historical_count(tmp_path: Path) -> None:
    require(RELEASES_JSON, OVERLAY_ZIP)
    rows = real_releases(PROFILE)
    for r in rows:
        require(Path(r["path"]))
    assert [r["id"] for r in rows] == EXPECTED["releases_oldest_first"]
    cfg_path = write_config(
        tmp_path / "checker.toml", data_dir=tmp_path / "data", game_root=tmp_path / "no_game",
        overlay=OVERLAY_ZIP, overlay_prefix="overlay/", baseline=None, backups=None,
        not_installed=("README.txt", "SHARED.txt"),
        releases=[{"id": r["id"], "path": Path(r["path"]).as_posix(), "profile": r["profile"],
                   "packaging": "full", "packaging_root": "mod-parent"} for r in rows])
    cfg = load_config(cfg_path)
    rules = load_rules(cfg.rules_path)
    mans = [manifest.composed_manifest(cfg, r.release_id, rules) for r in cfg.releases]
    assert {m.release_id: len(m.entries) for m in mans} == EXPECTED["entry_counts"]
    assert {m.release_id: m.source_sha256 for m in mans} == EXPECTED["release_sha256"]
    hits = history.find_aba(mans)
    assert len(hits) == EXPECTED["aba_count"]


def test_a02_synthetic_one_path_three_ids(tmp_path: Path) -> None:
    m = MOD + "/"
    zips = {
        "S1": write_zip(tmp_path / "S1.zip", [(m + "script/eur40/x.nut", b"A"), (m + "script/eur40/y.nut", b"1")]),
        "S2": write_zip(tmp_path / "S2.zip", [(m + "script/eur40/x.nut", b"B"), (m + "script/eur40/y.nut", b"2")]),
        "S3": write_zip(tmp_path / "S3.zip", [(m + "script/eur40/x.nut", b"A"), (m + "script/eur40/y.nut", b"3")]),
    }
    overlay = tmp_path / "overlay"
    write_tree(overlay, {"script/eur40/x.nut": b"A", "script/eur40/y.nut": b"3"})
    cfg_path = write_config(
        tmp_path / "checker.toml", data_dir=tmp_path / "data", game_root=tmp_path / "no_game",
        overlay=overlay, baseline=None, backups=None, not_installed=(),
        releases=[{"id": k, "path": v.as_posix(), "profile": PROFILE, "packaging": "full",
                   "packaging_root": "mod-parent"} for k, v in zips.items()])
    cfg = load_config(cfg_path)
    rules = load_rules(cfg.rules_path)
    store = Store(cfg.db_path)
    try:
        res = compare.run_version_checks(cfg, "S3", store, rules, include_live=False)
    finally:
        store.close()
    v03 = [f for f in res.findings if f.rule_id == "V03" and f.result is Verdict.FAIL]
    assert len(v03) == 1
    assert v03[0].normalized_path == "script/eur40/x.nut"
    for rid in ("S1", "S2", "S3"):
        assert rid in v03[0].message and rid in v03[0].observed_value
