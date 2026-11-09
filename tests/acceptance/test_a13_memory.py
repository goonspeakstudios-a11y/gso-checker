"""A13: unchanged second run is fully cached and says 'Verified <date>, unchanged'; changing
one dependent file re-runs only dependent findings; Fixed reopens only when re-evaluation
fails; Waived keeps reason/author/date and never changes the verdict."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from gso_checker import cli, compare, sheet
from gso_checker.model import CacheState, Verdict, WorkflowStatus
from tests.helpers import CORE_OLD, CORE_PATH, GSO_MAIN, build_world, load_world

NOW = "2026-11-08T00:00:00Z"


def _run(w):
    cfg, rules, store = load_world(w)
    try:
        return compare.run_check(cfg, "R-stale", store, rules)
    finally:
        store.close()


def _by(rep, rule: str, path: str):
    return next(r for r in rep.findings if r.finding.rule_id == rule and r.finding.normalized_path == path)


def _mark(w, rep, targets: dict[tuple[str, str], dict[str, str]], name: str) -> None:
    exp = sheet.export_sheet(rep.findings, w.root / "sheets", "R-stale")
    with exp.csv_path.open(encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    for row in rows:
        key = (row["rule_id"], row["file"])
        if key in targets:
            row.update(targets[key])
    rows.reverse()                       # import must not depend on row order
    out = w.root / "sheets" / name
    with out.open("w", encoding="utf-8", newline="") as fh:
        wr = csv.DictWriter(fh, fieldnames=list(sheet.SHEET_COLUMNS))
        wr.writeheader()
        wr.writerows(rows)
    cfg, rules, store = load_world(w)
    try:
        res = sheet.import_sheet(out, store, imported_at_utc=NOW)
    finally:
        store.close()
    assert len(res.accepted) == len(targets) and res.rejected == ()


def test_a13_second_run_cached_and_verified_line(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    one = _run(w)
    assert one.rechecked == len(one.findings) and one.cached == 0
    two = _run(w)
    assert two.cached == len(two.findings) and two.rechecked == 0
    assert all(r.finding.cache_state is CacheState.CACHED for r in two.findings)
    day = one.findings[0].finding.checked_at_utc[:10]
    out = io.StringIO()
    code = cli.main(["--config", str(w.config), "check", "--release", "R-stale"], stdout=out)
    assert code == cli.EXIT_FAIL
    text = out.getvalue()
    assert f"Verified {day}, unchanged" in text
    assert f"cached: {len(two.findings)} | rechecked: 0" in text


def test_a13_only_dependent_findings_rerun(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    _run(w)
    (w.overlay / "script/main.nut").write_bytes(GSO_MAIN + b"// repo edit\r\n")
    three = _run(w)
    rechecked = {(r.finding.rule_id, r.finding.normalized_path)
                 for r in three.findings if r.finding.cache_state is CacheState.RECHECKED}
    assert rechecked == {("V01", "script/main.nut"), ("V04", "script/main.nut")}
    assert three.rechecked == 2 and three.cached == len(three.findings) - 2


def test_a13_fixed_reopens_only_on_failing_reevaluation(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    rep = _run(w)
    assert _by(rep, "V04", CORE_PATH).finding.result is Verdict.FAIL
    _mark(w, rep, {("V04", CORE_PATH): {"Status": "Fixed", "Reviewer": "BB1"}}, "fixed.csv")

    # unrelated edit: the finding stays Fixed
    (w.overlay / "script/main.nut").write_bytes(GSO_MAIN + b"// unrelated\r\n")
    r1 = _by(_run(w), "V04", CORE_PATH)
    assert r1.status is WorkflowStatus.FIXED and r1.reopened is False

    # affected input changes and the rule now passes: still Fixed
    (w.overlay / CORE_PATH).write_bytes(CORE_OLD)
    r2 = _by(_run(w), "V04", CORE_PATH)
    assert r2.finding.result is Verdict.PASS and r2.status is WorkflowStatus.FIXED

    # affected input changes and the rule fails: reopened
    (w.overlay / CORE_PATH).write_bytes(b"// a third version\n")
    r3 = _by(_run(w), "V04", CORE_PATH)
    assert r3.finding.result is Verdict.FAIL
    assert r3.status is WorkflowStatus.OPEN and r3.reopened is True


def test_a13_waived_keeps_reason_and_verdict(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    rep = _run(w)
    reason = "author-approved: old core kept for this test build"
    _mark(w, rep, {("V01", CORE_PATH): {"Status": "Waived", "Reason": reason, "Reviewer": "BB1",
                                        "ReviewedAt": "2026-11-07T20:00:00Z"}}, "waive.csv")
    after = _run(w)
    r = _by(after, "V01", CORE_PATH)
    assert r.finding.result is Verdict.FAIL
    assert (r.status, r.reason, r.reviewer, r.reviewed_at) == (
        WorkflowStatus.WAIVED, reason, "BB1", "2026-11-07T20:00:00Z")
    assert after.verdict is Verdict.FAIL          # V04 on the same file is still open
    out = io.StringIO()
    cli.main(["--config", str(w.config), "check", "--release", "R-stale"], stdout=out)
    assert f"status: Waived | reason: {reason} | reviewer: BB1 | date: 2026-11-07T20:00:00Z" in out.getvalue()
