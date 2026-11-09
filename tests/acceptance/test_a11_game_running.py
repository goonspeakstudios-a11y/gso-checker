"""A11: injected 'game running' probe -> install-gate REFUSE with zero writes; unknown
process state -> REFUSE; waiver without reason -> REFUSE; waiver with reason keeps the
rule verdict FAIL."""

from __future__ import annotations

import io
from pathlib import Path

import pytest

from gso_checker import cli, gate, installer
from gso_checker.model import GateOutcome, GateRefusedError, Verdict, Waiver
from tests.helpers import (CORE_PATH, build_world, load_world, probe_not_running, probe_running,
                           probe_unknown, snapshot_tree)


def test_a11_running_refuses_without_writes(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    before = snapshot_tree(w.game_root)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_running, store=store, rules=rules)
        assert d.outcome is GateOutcome.REFUSE
        proc = next(c for c in d.checks if c.name == "process")
        assert proc.verdict is Verdict.FAIL
        assert "4242" in proc.reason and "M2EX.exe" in proc.reason
        assert d.process is not None and d.process.observed_at_utc
        with pytest.raises(GateRefusedError):
            installer.install(cfg, "R-good", confirm="R-good", probe=probe_running, store=store, rules=rules)
    finally:
        store.close()
    assert snapshot_tree(w.game_root) == before


def test_a11_cli_gate_running_exit_3_and_no_writes(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    before = snapshot_tree(w.game_root)
    out = io.StringIO()
    code = cli.main(["--config", str(w.config), "install-gate", "--release", "R-good"],
                    probe=probe_running, stdout=out)
    assert code == cli.EXIT_USAGE_OR_BLOCKED
    assert "DECISION: REFUSE" in out.getvalue()
    assert snapshot_tree(w.game_root) == before


def test_a11_unknown_process_state_refuses(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg, rules, store = load_world(w)
    try:
        d = gate.evaluate_gate(cfg, "R-good", probe=probe_unknown, store=store, rules=rules)
    finally:
        store.close()
    assert d.outcome is GateOutcome.REFUSE
    assert next(c for c in d.checks if c.name == "process").verdict is Verdict.UNKNOWN


def _stale_fail_ids(d) -> list[str]:
    return [f.finding_id for f in d.findings
            if f.result is Verdict.FAIL and f.normalized_path == CORE_PATH and f.rule_id in ("V01", "V04")]


def test_a11_waiver_without_reason_refuses(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg, rules, store = load_world(w)
    try:
        d0 = gate.evaluate_gate(cfg, "R-stale", probe=probe_not_running, store=store, rules=rules)
        ids = _stale_fail_ids(d0)
        assert len(ids) == 2
        empty = [Waiver(i, "", "BB1", "2026-11-08") for i in ids]
        d1 = gate.evaluate_gate(cfg, "R-stale", probe=probe_not_running, store=store, rules=rules, waivers=empty)
        assert d1.outcome is GateOutcome.REFUSE
        wv = next(c for c in d1.checks if c.name == "waivers")
        assert wv.verdict is Verdict.FAIL and "no reason" in wv.reason

        good = [Waiver(i, "author-approved: old core kept for test build", "BB1", "2026-11-08") for i in ids]
        d2 = gate.evaluate_gate(cfg, "R-stale", probe=probe_not_running, store=store, rules=rules, waivers=good)
        assert d2.outcome is GateOutcome.ALLOW
        man = next(c for c in d2.checks if c.name == "manifest")
        assert man.waived is True
        # the rule verdicts are unchanged by the waiver
        assert len(_stale_fail_ids(d2)) == 2
    finally:
        store.close()
