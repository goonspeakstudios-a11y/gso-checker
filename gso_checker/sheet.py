"""Review sheet export (CSV always, XLSX when openpyxl is importable) and import.

Contract: ARCHITECTURE.md 4.8.
"""

from __future__ import annotations

import csv
import importlib.util
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from gso_checker.model import (ConfigError, ReviewDecision, ReviewedFinding, WorkflowStatus)
from gso_checker.store import Store

logger = logging.getLogger(__name__)

# Spec section 8 columns, plus 'rule_version' (needed for the import key) after source_sha256.
SHEET_COLUMNS: tuple[str, ...] = (
    "finding_id", "rule_id", "profile", "file", "line", "actual_verdict", "expected", "actual",
    "evidence", "source_sha256", "rule_version", "checked_at",
    "Status", "Reason", "Reviewer", "ReviewedAt",
)
STATUS_VALUES: tuple[str, ...] = ("Open", "Fixed", "Waived", "Not a bug", "Engine")
XLSX_UNAVAILABLE_NOTE: str = "openpyxl not installed: CSV only, no XLSX written"
REQUIRED_HEADERS: tuple[str, ...] = ("finding_id", "source_sha256", "rule_version", "Status")


@dataclass(frozen=True)
class SheetExport:
    csv_path: Path
    xlsx_path: Path | None
    note: str                      # '' or XLSX_UNAVAILABLE_NOTE
    rows: int


@dataclass(frozen=True)
class ImportResult:
    accepted: tuple[ReviewDecision, ...]
    rejected: tuple[tuple[int, str, str], ...]   # (sheet row number 2.., finding_id, reason)


def xlsx_available() -> bool:
    """True when `import openpyxl` succeeds."""
    try:
        return importlib.util.find_spec("openpyxl") is not None
    except (ImportError, ValueError):
        return False


def _row_values(r: ReviewedFinding) -> list[str]:
    f = r.finding
    evidence = f.source_file_or_log
    if f.source_line_or_offset:
        evidence = f"{evidence} @ {f.source_line_or_offset}"
    return [
        f.finding_id, f.rule_id, f.profile_id, f.normalized_path,
        "" if f.line is None else str(f.line), f.result.value, f.expected_value,
        f.observed_value, evidence, f.source_sha256 or "", f.rule_version, f.checked_at_utc,
        r.status.value, r.reason, r.reviewer, r.reviewed_at,
    ]


def export_sheet(reviewed: Sequence[ReviewedFinding], out_dir: Path, release_id: str) -> SheetExport:
    """Write review_<release_id>.csv and, if openpyxl imports, review_<release_id>.xlsx."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ordered = sorted(reviewed, key=lambda r: (r.finding.rule_id, r.finding.normalized_path,
                                              -1 if r.finding.line is None else r.finding.line))
    rows = [_row_values(r) for r in ordered]
    csv_path = out_dir / f"review_{release_id}.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(SHEET_COLUMNS)
        w.writerows(rows)
    xlsx_path: Path | None = None
    note = ""
    if xlsx_available():
        xlsx_path = out_dir / f"review_{release_id}.xlsx"
        _write_xlsx(xlsx_path, rows)
    else:
        note = XLSX_UNAVAILABLE_NOTE
    return SheetExport(csv_path, xlsx_path, note, len(rows))


def _write_xlsx(path: Path, rows: list[list[str]]) -> None:
    from openpyxl import Workbook
    from openpyxl.worksheet.datavalidation import DataValidation

    wb = Workbook()
    ws = wb.active
    ws.title = "review"
    ws.append(list(SHEET_COLUMNS))
    for row in rows:
        ws.append(row)
    status_col = SHEET_COLUMNS.index("Status") + 1
    letter = ws.cell(row=1, column=status_col).column_letter
    dv = DataValidation(type="list", formula1='"' + ",".join(STATUS_VALUES) + '"',
                        allow_blank=True)
    ws.add_data_validation(dv)
    dv.add(f"{letter}2:{letter}{max(len(rows) + 1, 2) + 1000}")
    ws.freeze_panes = "A2"
    wb.save(str(path))


def read_sheet(path: Path) -> list[dict[str, str]]:
    """Rows of a .csv or .xlsx sheet as dicts keyed by header (all values str)."""
    path = Path(path)
    suffix = path.suffix.lower()
    if suffix == ".csv":
        with path.open(newline="", encoding="utf-8-sig") as fh:
            reader = csv.DictReader(fh)
            headers = list(reader.fieldnames or [])
            rows = [{k: (v or "") for k, v in r.items() if k is not None} for r in reader]
    elif suffix == ".xlsx":
        if not xlsx_available():
            raise ConfigError(XLSX_UNAVAILABLE_NOTE)
        from openpyxl import load_workbook
        wb = load_workbook(str(path), read_only=True, data_only=True)
        try:
            ws = wb.active
            it = ws.iter_rows(values_only=True)
            first = next(it, None)
            headers = [] if first is None else ["" if c is None else str(c) for c in first]
            rows = []
            for vals in it:
                if all(v is None or v == "" for v in vals):
                    continue
                rows.append({h: ("" if v is None else str(v)) for h, v in zip(headers, vals)})
        finally:
            wb.close()
    else:
        raise ConfigError(f"unsupported sheet type: {path.suffix!r} (use .csv or .xlsx)")
    missing = [h for h in REQUIRED_HEADERS if h not in headers]
    if missing:
        raise ConfigError("sheet is missing required column(s): " + ", ".join(missing))
    return rows


def import_sheet(path: Path, store: Store, *, imported_at_utc: str) -> ImportResult:
    """Import human decisions keyed by finding_id + source_sha256 + rule_version."""
    accepted: list[ReviewDecision] = []
    rejected: list[tuple[int, str, str]] = []
    for n, row in enumerate(read_sheet(path), start=2):
        fid = row.get("finding_id", "").strip()
        status_text = row.get("Status", "").strip()
        if not status_text:
            continue
        latest_dec = store.latest_decision(fid)
        if status_text == "Open" and (latest_dec is None
                                      or latest_dec.status is WorkflowStatus.OPEN):
            continue
        finding = store.latest_finding(fid)
        if finding is None:
            rejected.append((n, fid, "unknown finding"))
            continue
        if ((row.get("source_sha256", "").strip() != (finding.source_sha256 or ""))
                or row.get("rule_version", "").strip() != finding.rule_version):
            rejected.append((n, fid, "stale row: source hash or rule version changed"))
            continue
        if status_text not in STATUS_VALUES:
            rejected.append((n, fid, "invalid status"))
            continue
        status = WorkflowStatus(status_text)
        reason = row.get("Reason", "").strip()
        reviewer = row.get("Reviewer", "").strip()
        if status is WorkflowStatus.WAIVED and not reason:
            rejected.append((n, fid, "Waived requires a reason"))
            continue
        if status is WorkflowStatus.WAIVED and not reviewer:
            rejected.append((n, fid, "Waived requires a reviewer"))
            continue
        decision = ReviewDecision(
            fid, finding.source_sha256, finding.rule_version, finding.dependency_fingerprint,
            status, reason, reviewer, row.get("ReviewedAt", "").strip() or imported_at_utc,
            str(path))
        store.add_decision(decision)
        accepted.append(decision)
    return ImportResult(tuple(accepted), tuple(rejected))
