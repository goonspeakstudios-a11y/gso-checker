"""Unit: checker.toml loading, rules catalog, glob matching."""

from __future__ import annotations

from pathlib import Path

import pytest

from gso_checker import config
from gso_checker.model import ConfigError, Packaging, PackagingRoot
from tests.helpers import MOD, PROFILE, PROJECT_ROOT, RULES_PATH, build_world


def test_load_config_from_world(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg = config.load_config(w.config)
    assert cfg.profile_id == PROFILE
    assert cfg.live_mod == w.game_root / "mods" / MOD
    assert cfg.eur_baseline == w.baseline
    assert [r.release_id for r in cfg.releases] == ["R-stale", "R-good"]
    assert [r.order for r in cfg.releases] == [0, 1]
    assert cfg.releases[0].packaging is Packaging.FULL
    assert cfg.releases[0].packaging_root is PackagingRoot.MOD_PARENT
    assert cfg.db_path == w.data_dir / "checker.db"
    assert cfg.reports_dir == w.data_dir / "reports"
    assert ".nut" in cfg.text_extensions


def test_empty_baseline_is_none(tmp_path: Path) -> None:
    w = build_world(tmp_path, baseline=False)
    cfg = config.load_config(w.config)
    assert cfg.eur_baseline is None


def test_example_toml_parses_with_seven_eurex_releases() -> None:
    cfg = config.load_config(PROJECT_ROOT / "checker.example.toml")
    assert cfg.profile_id == "EUREX-1.5"
    assert cfg.eur_baseline is None
    assert len(cfg.releases) == 7
    assert all(r.profile_id == "EUREX-1.5" for r in cfg.releases)
    assert cfg.releases[-1].release_id == "0.5.4e"
    assert cfg.repo_overlay_prefix == "overlay/"


def test_missing_required_key_raises(tmp_path: Path) -> None:
    p = tmp_path / "bad.toml"
    p.write_text('[checker]\nprofile = "EUREX-1.5"\n', encoding="utf-8")
    with pytest.raises(ConfigError):
        config.load_config(p)


def test_patch_without_parent_raises(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    text = w.config.read_text(encoding="utf-8").replace('packaging = "full"', 'packaging = "patch"', 1)
    w.config.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError):
        config.load_config(w.config)


def test_release_by_id_unknown_raises(tmp_path: Path) -> None:
    cfg = config.load_config(build_world(tmp_path).config)
    assert config.release_by_id(cfg, "R-good").release_id == "R-good"
    with pytest.raises(ConfigError):
        config.release_by_id(cfg, "nope")


@pytest.mark.parametrize("path,pattern,want", [
    ("script/eur40/a.nut", "script/eur40/**", True),
    ("script/eur40/sub/b.nut", "script/eur40/**", True),
    ("script/eur40x/a.nut", "script/eur40/**", False),
    ("SCRIPT/EUR40/A.NUT", "script/eur40/**", True),
    ("eopData/sounds/eur40_rain.wav", "eopData/sounds/eur40_*", True),
    ("eopData/sounds/sub/eur40_rain.wav", "eopData/sounds/eur40_*", False),
    ("GSO_Uninstall.bat", "GSO_Uninstall.bat", True),
    ("data/text/menu_english.txt", "script/eur40/**", False),
])
def test_match_glob(path: str, pattern: str, want: bool) -> None:
    assert config.match_glob(path, pattern) is want


def test_rules_catalog_phase1() -> None:
    rules = config.load_rules(RULES_PATH)
    assert sorted(rules) == ["V01", "V02", "V03", "V04", "V05", "V06", "V07"]
    for r in rules.values():
        assert r.authority in {"documented", "observed", "policy", "hypothesis"}
        assert r.severity in {"blocking", "info"}
        assert r.version and r.message and r.evidence
    assert rules["V06"].waivable is False and rules["V07"].waivable is False
    assert config.rule_applies(rules["V07"], "anything")
    assert config.rule_applies(rules["V01"], "EUREX-1.5")
    assert not config.rule_applies(rules["V01"], "EUR-2.085-EUREX-1.4.2")
