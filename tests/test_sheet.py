"""Unit: review sheet export/import keyed by finding_id + source hash + rule version."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from gso_checker import sheet
from gso_checker.model import Finding, ReviewedFinding, Verdict, WorkflowStatus
from gso_checker.store import Store
from tests.helpers import PROFILE

NOW = "2026-11-08T00:00:00Z"


def f(fid: str, path: str, src: str) -> Finding:
    return Finding(fid, "V04", PROFILE, "R1", path, None, Verdict.FAIL, "m", "obs", "exp",
                   "R1.zip!" + path, None, src, "1", NOW, "fp-" + fid, waivable=True)


@pytest.fixture()
def setup(tmp_path: Path):
    store = Store(tmp_path / "c.db")
    fs = [f("f1", "a.nut", "1" * 64), f("f2", "b.nut", "2" * 64), f("f3", "c.nut", "3" * 64)]
    store.record_findings("run1", "check", fs)
    yield tmp_path, store, fs
    store.close()


def write_rows(path: Path, rows: list[dict[str, str]]) -> Path:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(sheet.SHEET_COLUMNS))
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in sheet.SHEET_COLUMNS})
    return path


def test_export_csv_columns_and_rows(setup) -> None:
    tmp, store, fs = setup
    out = sheet.export_sheet([ReviewedFinding(x, WorkflowStatus.OPEN) for x in fs], tmp / "out", "R1")
    assert out.csv_path.name == "review_R1.csv" and out.rows == 3
    with out.csv_path.open(encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        header = next(reader)
        body = list(reader)
    assert tuple(header) == sheet.SHEET_COLUMNS
    assert "rule_version" in header
    assert body[0][header.index("Status")] == "Open"
    if sheet.xlsx_available():
        assert out.xlsx_path is not None and out.xlsx_path.exists() and out.note == ""
    else:
        assert out.xlsx_path is None and out.note == sheet.XLSX_UNAVAILABLE_NOTE


def test_import_by_id_not_row_order(setup) -> None:
    tmp, store, fs = setup
    rows = [
        {"finding_id": "f3", "source_sha256": "3" * 64, "rule_version": "1", "Status": "Not a bug",
         "Reason": "doc", "Reviewer": "BB1"},
        {"finding_id": "f1", "source_sha256": "1" * 64, "rule_version": "1", "Status": "Fixed",
         "Reason": "", "Reviewer": "BB1"},
        {"finding_id": "f2", "source_sha256": "2" * 64, "rule_version": "1", "Status": ""},
    ]
    res = sheet.import_sheet(write_rows(tmp / "r.csv", rows), store, imported_at_utc=NOW)
    assert {d.finding_id: d.status for d in res.accepted} == {
        "f3": WorkflowStatus.NOT_A_BUG, "f1": WorkflowStatus.FIXED}
    assert res.rejected == ()
    assert store.latest_decision("f1").status is WorkflowStatus.FIXED
    assert store.latest_decision("f1").dependency_fingerprint == "fp-f1"
    assert store.latest_decision("f2") is None


def test_import_rejections(setup) -> None:
    tmp, store, fs = setup
    rows = [
        {"finding_id": "f1", "source_sha256": "9" * 64, "rule_version": "1", "Status": "Fixed"},
        {"finding_id": "f2", "source_sha256": "2" * 64, "rule_version": "7", "Status": "Fixed"},
        {"finding_id": "f3", "source_sha256": "3" * 64, "rule_version": "1", "Status": "Waived",
         "Reason": "", "Reviewer": "BB1"},
        {"finding_id": "zz", "source_sha256": "0" * 64, "rule_version": "1", "Status": "Fixed"},
        {"finding_id": "f1", "source_sha256": "1" * 64, "rule_version": "1", "Status": "Done"},
    ]
    res = sheet.import_sheet(write_rows(tmp / "r.csv", rows), store, imported_at_utc=NOW)
    assert res.accepted == ()
    reasons = {(row, fid): why for row, fid, why in res.rejected}
    assert reasons[(2, "f1")].startswith("stale row")
    assert reasons[(3, "f2")].startswith("stale row")
    assert reasons[(4, "f3")] == "Waived requires a reason"
    assert reasons[(5, "zz")] == "unknown finding"
    assert reasons[(6, "f1")] == "invalid status"
    assert store.latest_decision("f3") is None


def test_waived_keeps_reason_author_date(setup) -> None:
    tmp, store, fs = setup
    rows = [{"finding_id": "f2", "source_sha256": "2" * 64, "rule_version": "1", "Status": "Waived",
             "Reason": "author-approved temporary HUD", "Reviewer": "BB1", "ReviewedAt": "2026-11-07"}]
    res = sheet.import_sheet(write_rows(tmp / "r.csv", rows), store, imported_at_utc=NOW)
    d = res.accepted[0]
    assert (d.status, d.reason, d.reviewer, d.reviewed_at) == (
        WorkflowStatus.WAIVED, "author-approved temporary HUD", "BB1", "2026-11-07")


def test_read_sheet_rejects_missing_header(tmp_path: Path) -> None:
    from gso_checker.model import ConfigError
    p = tmp_path / "bad.csv"
    p.write_text("finding_id,Status\nf1,Fixed\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        sheet.read_sheet(p)


@pytest.mark.skipif(not __import__("importlib").util.find_spec("openpyxl"), reason="openpyxl not installed")
def test_xlsx_roundtrip(setup) -> None:
    tmp, store, fs = setup
    out = sheet.export_sheet([ReviewedFinding(x, WorkflowStatus.OPEN) for x in fs], tmp / "out", "R1")
    rows = sheet.read_sheet(out.xlsx_path)
    assert [r["finding_id"] for r in rows] == ["f1", "f2", "f3"]
    assert rows[0]["Status"] == "Open"
