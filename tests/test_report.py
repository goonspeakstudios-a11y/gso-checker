"""Unit: roll-up and report text format (spec section 9)."""

from __future__ import annotations

import dataclasses
import io
import json
from pathlib import Path

from gso_checker import report
from gso_checker.model import (CacheState, Finding, Report, ReviewedFinding, Verdict,
                               WorkflowStatus)
from tests.helpers import PROFILE


def f(rule: str, result: Verdict, *, waivable: bool = True, blocking: bool = True,
      path: str = "script/eur40/eur40BattleHud.nut") -> Finding:
    return Finding(f"id-{rule}-{result.value}", rule, PROFILE, "0.5.4e", path, None, result,
                   "Battle HUD file in release does not match repo; different from repo.",
                   "a" * 64, "b" * 64, "E:/GSO_054/GSO_0.5.4e.zip!x", None, "a" * 64, "1",
                   "2026-11-08T10:00:00Z", "fp", blocking=blocking, waivable=waivable)


def rf(x: Finding, status: WorkflowStatus = WorkflowStatus.OPEN, **kw: object) -> ReviewedFinding:
    return ReviewedFinding(x, status, **kw)


def test_rollup() -> None:
    p, u, fl = f("V01", Verdict.PASS), f("V06", Verdict.UNKNOWN), f("V04", Verdict.FAIL)
    i = f("V05", Verdict.INFO, blocking=False)
    assert report.rollup([rf(p, WorkflowStatus.NONE)]) is Verdict.PASS
    assert report.rollup([rf(p), rf(i)]) is Verdict.PASS
    assert report.rollup([rf(p), rf(u)]) is Verdict.UNKNOWN
    assert report.rollup([rf(p), rf(u), rf(fl)]) is Verdict.FAIL
    assert report.rollup([rf(p), rf(fl, WorkflowStatus.WAIVED, reason="ok")]) is Verdict.PASS
    nw = f("V07", Verdict.FAIL, waivable=False)
    assert report.rollup([rf(nw, WorkflowStatus.WAIVED, reason="ok")]) is Verdict.FAIL
    assert report.rollup([]) is Verdict.UNKNOWN


def test_count_line() -> None:
    items = [rf(f("V01", Verdict.PASS)), rf(f("V04", Verdict.FAIL)), rf(f("V06", Verdict.UNKNOWN)),
             rf(f("V03", Verdict.FAIL), WorkflowStatus.WAIVED, reason="x")]
    assert report.count_line(items) == (1, 1, 1)


def test_ascii_safe() -> None:
    assert report.ascii_safe("caf\u00e9 \u2014 ok") == "caf? ? ok"


def test_render_text_header_and_finding_block() -> None:
    fl = dataclasses.replace(f("V04", Verdict.FAIL), cache_state=CacheState.CACHED)
    rep = Report(command="check", profile_id=PROFILE, release_id="0.5.4e", verdict=Verdict.FAIL,
                 reason="The release differs from two required repository files.",
                 findings=(rf(fl, verified_on="2026-11-08"),), cached=1, rechecked=0,
                 text_path="C:/data/reports/20261108T100000Z_check.txt")
    text = report.render_text(rep)
    lines = text.splitlines()
    assert lines[0] == "GSO CHECKER | profile: EUREX-1.5 | release: 0.5.4e"
    assert lines[1] == "VERDICT: FAIL | 1 blocking | 0 unknown | 0 passed"
    assert lines[2] == "Reason: The release differs from two required repository files."
    assert lines[3] == "cached: 1 | rechecked: 0"
    assert "FAIL V04 | Battle HUD file in release does not match repo; different from repo." in lines
    assert "  path: script/eur40/eur40BattleHud.nut" in lines
    assert f"  observed: {'a' * 64} | expected: {'b' * 64}" in lines
    assert "  Verified 2026-11-08, unchanged" in lines
    assert lines[-1] == "Full report: C:/data/reports/20261108T100000Z_check.txt"
    assert text.isascii()


def test_render_text_hides_pass_unless_asked() -> None:
    p = f("V01", Verdict.PASS)
    rep = Report("check", PROFILE, "R1", Verdict.PASS, "All good.", (rf(p, WorkflowStatus.NONE),))
    assert "PASS V01 |" not in report.render_text(rep)
    assert "PASS V01 |" in report.render_text(rep, show_pass=True)


def test_write_report_and_emit(tmp_path: Path) -> None:
    rep = Report("sources", PROFILE, "-", None, "Inventory of configured inputs.")
    out = report.write_report(rep, tmp_path / "reports", "20261108T100000Z")
    assert out.text_path and out.text_path.endswith("20261108T100000Z_sources.txt")
    assert Path(out.json_path).exists()
    data = json.loads(Path(out.json_path).read_text(encoding="ascii"))
    assert data["command"] == "sources"
    buf = io.StringIO()
    report.emit("x \u00e9", buf)
    assert buf.getvalue() == "x ?\n"
