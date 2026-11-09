"""A03: a live-only stall-watch script under a GSO-owned path is reported with its sha256;
an EUR file outside the owned globs is not flagged. The real stall-watch file is only READ
from E: and copied into a tmp fake live tree."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from gso_checker import compare, config, manifest
from gso_checker.model import Verdict
from tests.helpers import (CORE_NEW, CORE_PATH, PROFILE, STALLWATCH, build_world, require, sha,
                           write_tree)

STALL_PATH = "script/eur40/eur40StallWatch.nut"


def _live_with_stallwatch(tmp_path: Path, source: bytes | None = None):
    w = build_world(tmp_path)
    target = w.live / STALL_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    if source is None:
        shutil.copyfile(STALLWATCH, target)
    else:
        target.write_bytes(source)
    write_tree(w.live, {CORE_PATH: CORE_NEW, "data/eur_only_extra.txt": b"EUR data, not GSO\r\n"})
    cfg = config.load_config(w.config)
    rules = config.load_rules(cfg.rules_path)
    return w, cfg, rules, target


def _v05(cfg, rules, known: set[str] = frozenset()):
    live = manifest.build_tree_manifest(cfg.live_mod, release_id="live", kind="live", profile_id=PROFILE,
                                        text_extensions=cfg.text_extensions,
                                        include=lambda p: config.is_gso_owned(cfg, p))
    repo = manifest.build_overlay_manifest(cfg)
    return compare.rule_v05(live, repo, set(known), cfg, rules["V05"], "2026-11-08T00:00:00Z", "fp")


@pytest.mark.real
def test_a03_real_stallwatch_reported(tmp_path: Path) -> None:
    require(STALLWATCH)
    w, cfg, rules, target = _live_with_stallwatch(tmp_path)
    fs = _v05(cfg, rules)
    assert len(fs) == 1
    f = fs[0]
    assert f.rule_id == "V05" and f.normalized_path == STALL_PATH
    assert "live, not in repo, not in any manifest" in f.message
    assert f.observed_value == sha(STALLWATCH.read_bytes()) == f.source_sha256
    assert f.result is Verdict.INFO and f.blocking is False
    assert f.input_id == "live"


def test_a03_synthetic_eur_file_not_flagged_and_manifest_known(tmp_path: Path) -> None:
    w, cfg, rules, target = _live_with_stallwatch(tmp_path, source=b"// stall watch\n")
    paths = [f.normalized_path for f in _v05(cfg, rules)]
    assert paths == [STALL_PATH]
    assert "data/eur_only_extra.txt" not in paths
    assert _v05(cfg, rules, known={STALL_PATH.casefold()}) == []


def test_a03_block_extras_makes_fail(tmp_path: Path) -> None:
    w, cfg, rules, target = _live_with_stallwatch(tmp_path, source=b"// stall watch\n")
    cfg2 = type(cfg)(**{**cfg.__dict__, "block_extras": True})
    fs = _v05(cfg2, rules)
    assert len(fs) == 1 and fs[0].result is Verdict.FAIL and fs[0].blocking is True
