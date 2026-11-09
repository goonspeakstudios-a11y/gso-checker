"""Review sheet export (CSV always, XLSX when openpyxl is importable) and import.

Contract: ARCHITECTURE.md 4.8.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from gso_checker.model import ReviewDecision, ReviewedFinding
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
    raise NotImplementedError


def export_sheet(reviewed: Sequence[ReviewedFinding], out_dir: Path, release_id: str) -> SheetExport:
    """Write '<out_dir>/review_<release_id>.csv' (UTF-8, header = SHEET_COLUMNS,
    one row per finding sorted by (rule_id, file, line)) and, if xlsx_available(),
    'review_<release_id>.xlsx' with the same columns and a list data-validation on
    Status limited to STATUS_VALUES. Column mapping: profile=profile_id,
    file=normalized_path, line='' or int, actual_verdict=result.value,
    expected=expected_value, actual=observed_value,
    evidence=source_file_or_log[+ ' @ ' + source_line_or_offset],
    checked_at=checked_at_utc, Status/Reason/Reviewer/ReviewedAt from the
    workflow status (NONE -> '')."""
    raise NotImplementedError


def read_sheet(path: Path) -> list[dict[str, str]]:
    """Rows of a .csv or .xlsx sheet as dicts keyed by header (all values str,
    None -> ''). Unknown extension -> ConfigError. Missing required header
    (finding_id, source_sha256, rule_version, Status) -> ConfigError."""
    raise NotImplementedError


def import_sheet(path: Path, store: Store, *, imported_at_utc: str) -> ImportResult:
    """Import human decisions keyed by finding_id + source_sha256 + rule_version.

    Row order is irrelevant. For each row (row number = 2 for the first data row):
      Status '' -> skipped silently (not accepted, not rejected).
      Status 'Open' while the finding has no stored decision (or its latest
        decision is already Open) -> skipped silently (no change to record).
      finding_id unknown to store.latest_finding -> reject 'unknown finding'.
      source_sha256 or rule_version differ from the latest finding -> reject
        'stale row: source hash or rule version changed'.
      Status not in STATUS_VALUES -> reject 'invalid status'.
      Status 'Waived' with empty Reason -> reject 'Waived requires a reason'.
      Status 'Waived' with empty Reviewer -> reject 'Waived requires a reviewer'.
      Otherwise accept: ReviewDecision(dependency_fingerprint = latest finding's,
        reviewed_at = ReviewedAt or imported_at_utc, imported_from = str(path)),
        store.add_decision.
    """
    raise NotImplementedError
