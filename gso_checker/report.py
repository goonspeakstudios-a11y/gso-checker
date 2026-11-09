"""Verdict roll-up and report rendering (.txt + .json). Contract: ARCHITECTURE.md 4.13 and 8."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence, TextIO

from gso_checker.model import Finding, Report, ReviewedFinding, Verdict

logger = logging.getLogger(__name__)

HEADER_FORMAT: str = "GSO CHECKER | profile: {profile} | release: {release}"
VERDICT_FORMAT: str = "VERDICT: {verdict} | {blocking} blocking | {unknown} unknown | {passed} passed"
COUNTS_FORMAT: str = "cached: {cached} | rechecked: {rechecked}"
VERIFIED_FORMAT: str = "  Verified {date}, unchanged"


def rollup(reviewed: Sequence[ReviewedFinding]) -> Verdict:
    """Spec section 2 roll-up. FAIL if any finding with result FAIL, blocking
    True and status != WAIVED (a WAIVED status only counts when
    finding.waivable is True; a non-waivable FAIL stays blocking even if a
    sheet says Waived). Else UNKNOWN if any UNKNOWN finding (blocking True).
    Else PASS. INFO never affects the roll-up. Empty input -> UNKNOWN."""
    raise NotImplementedError


def count_line(reviewed: Sequence[ReviewedFinding]) -> tuple[int, int, int]:
    """(blocking, unknown, passed): blocking = FAIL findings that make the
    roll-up FAIL (per rollup's rule); unknown = UNKNOWN findings; passed = PASS."""
    raise NotImplementedError


def ascii_safe(text: str) -> str:
    """Replace every non-ASCII char with '?'. All console/report text goes through it."""
    raise NotImplementedError


def render_finding(item: ReviewedFinding) -> list[str]:
    """Lines for one finding, exactly:
      '<RESULT> <rule_id> | <message>'
      '  path: <normalized_path>[:<line>]'
      '  observed: <observed_value> | expected: <expected_value>'
      '  evidence: <source_file_or_log>[ @ <source_line_or_offset>] | sha256: <source_sha256 or ->'
      '  status: <status>[ | reason: <r> | reviewer: <who> | date: <when>][ (reopened)]'   (only if status != NONE)
      VERIFIED_FORMAT line                                                           (only if cached)
    """
    raise NotImplementedError


def render_text(report: Report, *, show_pass: bool = False) -> str:
    """Full stdout/.txt text (ARCHITECTURE.md section 8):
      line 1 HEADER_FORMAT; line 2 VERDICT_FORMAT (commands with verdict None
      print 'VERDICT: n/a'); line 3 'Reason: <reason>'; line 4 COUNTS_FORMAT;
      blank; body_lines; blank; findings ordered FAIL, UNKNOWN, INFO (then PASS
      when show_pass) each followed by a blank line; last line
      'Full report: <text_path>' when text_path is set. ASCII only, '\n' endings."""
    raise NotImplementedError


def render_json(report: Report) -> str:
    """json.dumps of the report (findings with every Finding field, enums as
    values, plus status fields), indent=2, sort_keys=True, ensure_ascii=True."""
    raise NotImplementedError


def write_report(report: Report, reports_dir: Path, stamp: str) -> Report:
    """Write '<reports_dir>/<stamp>_<command>.txt' and '.json' (create dir),
    return a copy of report with text_path/json_path set. stamp is
    'YYYYMMDDTHHMMSSZ'. The .txt holds render_text of the returned report."""
    raise NotImplementedError


def emit(text: str, stream: TextIO) -> None:
    """The ONLY console writer in the package (CLI final report). Writes
    ascii_safe(text) and a trailing newline to stream."""
    raise NotImplementedError


def findings_only(reviewed: Sequence[ReviewedFinding]) -> list[Finding]:
    """Convenience: [r.finding for r in reviewed]."""
    raise NotImplementedError
