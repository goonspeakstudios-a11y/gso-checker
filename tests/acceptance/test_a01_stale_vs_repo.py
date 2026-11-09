"""A01: 0.5.4e vs repo overlay -> battle HUD and Aragorn quest FAIL 'different from repo'
with both hashes. Reads the real corpus on E: (read-only); skips if missing."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from gso_checker import cli, compare
from gso_checker.config import load_config, load_rules
from gso_checker.model import Verdict
from gso_checker.store import Store
from tests.helpers import (OVERLAY_ZIP, PROFILE, PROJECT_ROOT, REL_054E, probe_not_running, require,
                           write_config)

EXPECTED = json.loads((PROJECT_ROOT / "fixtures" / "expected" / "a01_stale_files.json").read_text(encoding="utf-8"))


def real_cfg(tmp_path: Path) -> Path:
    return write_config(
        tmp_path / "checker.toml", data_dir=tmp_path / "data", game_root=tmp_path / "no_game",
        overlay=OVERLAY_ZIP, overlay_prefix="overlay/", baseline=None, backups=None,
        not_installed=("README.txt", "SHARED.txt"),
        releases=[{"id": "0.5.4e", "path": REL_054E.as_posix(), "profile": PROFILE,
                   "packaging": "full", "packaging_root": "mod-parent"}])


@pytest.mark.real
def test_a01_findings(tmp_path: Path) -> None:
    require(OVERLAY_ZIP, REL_054E)
    cfg = load_config(real_cfg(tmp_path))
    rules = load_rules(cfg.rules_path)
    store = Store(cfg.db_path)
    try:
        res = compare.run_version_checks(cfg, "0.5.4e", store, rules, include_live=False)
    finally:
        store.close()
    for path, h in EXPECTED["stale_files"].items():
        for rule_id in ("V01", "V04"):
            hits = [f for f in res.findings
                    if f.rule_id == rule_id and f.normalized_path.casefold() == path.casefold()]
            assert len(hits) == 1, (rule_id, path)
            f = hits[0]
            assert f.result is Verdict.FAIL
            assert f.observed_value == h["release_sha256"]
            assert f.expected_value == h["repo_sha256"]
            assert f.source_sha256 == h["release_sha256"]
            assert f.profile_id == PROFILE and f.input_id == "0.5.4e"
        v04 = next(f for f in res.findings if f.rule_id == "V04" and f.normalized_path.casefold() == path.casefold())
        assert "different from repo" in v04.message
        assert "older" not in v04.message.lower()
    main_nut = [f for f in res.findings if f.rule_id == "V04" and f.normalized_path == "script/main.nut"]
    assert main_nut and main_nut[0].result is Verdict.PASS


@pytest.mark.real
def test_a01_cli_compare_output(tmp_path: Path) -> None:
    require(OVERLAY_ZIP, REL_054E)
    cfg_path = real_cfg(tmp_path)
    out = io.StringIO()
    code = cli.main(["--config", str(cfg_path), "compare", "--release", "0.5.4e"],
                    probe=probe_not_running, stdout=out)
    text = out.getvalue()
    assert code == cli.EXIT_FAIL
    assert text.splitlines()[0] == "GSO CHECKER | profile: EUREX-1.5 | release: 0.5.4e"
    assert text.splitlines()[1].startswith("VERDICT: FAIL | ")
    for h in EXPECTED["stale_files"].values():
        assert h["release_sha256"] in text and h["repo_sha256"] in text
    assert "different from repo" in text
    assert "Full report: " in text
    assert text.isascii()
