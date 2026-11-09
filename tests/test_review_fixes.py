"""Regression tests for the phase-1 review fixes (2026-11-08)."""

from __future__ import annotations

import dataclasses
import io
from pathlib import Path

import pytest

from gso_checker import cli, compare, config, gate, installer, manifest, report
from gso_checker.model import (CacheState, CheckerError, Finding, GateOutcome, ReviewedFinding,
                               Verdict, WorkflowStatus)
from tests.helpers import (PROFILE, build_world, load_world, probe_not_running, write_config)


def _finding(result: Verdict, blocking: bool) -> Finding:
    return Finding("f" * 16, "V06", PROFILE, "R", "a.txt", None, result, "m", "o", "e", "s", None,
                   None, "1", "2026-11-08T00:00:00Z", "fp", blocking, False, CacheState.RECHECKED)


def test_rollup_never_turns_a_non_blocking_unknown_into_pass() -> None:
    items = [ReviewedFinding(_finding(Verdict.PASS, False), WorkflowStatus.NONE),
             ReviewedFinding(_finding(Verdict.UNKNOWN, False), WorkflowStatus.OPEN)]
    assert report.rollup(items) is Verdict.UNKNOWN


def test_v04_history_input_ignores_snapshots_holding_the_current_repo_sha() -> None:
    a = [("repo@1", "aaa", "2026-11-01T00:00:00Z")]
    b = a + [("repo@2", "cur", "2026-11-02T00:00:00Z"), ("repo@3", "cur", "2026-11-03T00:00:00Z")]
    assert compare._v04_history_input(a, "cur") == compare._v04_history_input(b, "cur")
    c = a + [("repo@4", "bbb", "2026-11-04T00:00:00Z")]
    assert compare._v04_history_input(a, "cur") != compare._v04_history_input(c, "cur")


def test_sources_phase2_input_unset_does_not_make_exit_2(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg, _rules, store = load_world(w)
    store.close()
    rows = {s.name: s for s in config.resolve_sources(cfg)}
    assert rows["repo_tools"].note == "not configured (phase 2)"
    assert config.is_phase2_source(rows["repo_tools"])
    out = io.StringIO()
    code = cli.main(["--config", str(w.config), "sources"], stdout=out)
    assert code == cli.EXIT_PASS, out.getvalue()
    assert "phase-2 input(s) not configured yet" in out.getvalue()


def test_sources_required_input_missing_still_exit_2(tmp_path: Path) -> None:
    w = build_world(tmp_path, baseline=False)
    out = io.StringIO()
    assert cli.main(["--config", str(w.config), "sources"], stdout=out) == cli.EXIT_UNKNOWN


def _world_with_declared(tmp_path: Path, declared: str):
    w = build_world(tmp_path)
    write_config(w.config, data_dir=w.data_dir, game_root=w.game_root, overlay=w.overlay,
                 baseline=w.baseline, backups=w.backups,
                 releases=[{"id": "R-good", "path": w.good_zip.as_posix(), "profile": PROFILE,
                            "packaging": "full", "packaging_root": "mod-parent",
                            "sha256": declared}])
    return w


def test_gate_refuses_zip_that_does_not_match_its_declared_sha(tmp_path: Path) -> None:
    w = _world_with_declared(tmp_path, "0" * 64)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_not_running, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.REFUSE
    m = next(c for c in d.checks if c.name == "manifest")
    assert m.verdict is Verdict.FAIL and "declared" in m.reason and not m.waivable
    out = io.StringIO()
    assert cli.main(["--config", str(w.config), "sources"], stdout=out) == cli.EXIT_FAIL


def test_gate_allows_when_declared_sha_matches(tmp_path: Path) -> None:
    from tests.helpers import sha
    w = build_world(tmp_path)
    w = _world_with_declared(tmp_path / "x", sha(w.good_zip.read_bytes()))
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_not_running, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.ALLOW, [(c.name, c.reason) for c in d.checks]


def test_checker_output_inside_game_folder_is_refused(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    before = sorted(p for p in w.game_root.rglob("*"))
    out = io.StringIO()
    code = cli.main(["--config", str(w.config), "sheet", "export", "--release", "R-good",
                     "--out", str(w.game_root / "sheets")], stdout=out)
    assert code == cli.EXIT_USAGE_OR_BLOCKED and "inside the game folder" in out.getvalue()
    assert sorted(p for p in w.game_root.rglob("*")) == before


def test_install_refuses_release_changed_after_gate(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    w = build_world(tmp_path)
    cfg, rules, store = load_world(w)
    real = manifest.composed_manifest

    def changed(*a: object, **k: object) -> object:
        """The installer's own re-read after the gate sees different bytes."""
        m = real(*a, **k)  # type: ignore[arg-type]
        e = m.entries[0]
        return dataclasses.replace(m, entries=(dataclasses.replace(e, sha256="9" * 64),) + m.entries[1:])

    monkeypatch.setattr(installer, "composed_manifest", changed)
    before = sorted(p.relative_to(w.live).as_posix() for p in w.live.rglob("*"))
    try:
        with pytest.raises(CheckerError, match="changed after the gate"):
            installer.install(cfg, "R-good", confirm="R-good", probe=probe_not_running,
                              store=store, rules=rules)
    finally:
        store.close()
    assert sorted(p.relative_to(w.live).as_posix() for p in w.live.rglob("*")) == before
