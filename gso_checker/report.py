"""Verdict roll-up and report rendering (.txt + .json). Contract: ARCHITECTURE.md 4.13 and 8."""

from __future__ import annotations

import dataclasses
import json
import logging
from enum import Enum
from pathlib import Path
from typing import Sequence, TextIO

from gso_checker.model import CacheState, Finding, Report, ReviewedFinding, Verdict, WorkflowStatus

logger = logging.getLogger(__name__)

HEADER_FORMAT: str = "GSO CHECKER | profile: {profile} | release: {release}"
VERDICT_FORMAT: str = "VERDICT: {verdict} | {blocking} blocking | {unknown} unknown | {passed} passed"
COUNTS_FORMAT: str = "cached: {cached} | rechecked: {rechecked}"
VERIFIED_FORMAT: str = "  Verified {date}, unchanged"


def _is_blocking_fail(item: ReviewedFinding) -> bool:
    f = item.finding
    if f.result is not Verdict.FAIL or not f.blocking:
        return False
    return not (item.status is WorkflowStatus.WAIVED and f.waivable)


def rollup(reviewed: Sequence[ReviewedFinding]) -> Verdict:
    """Spec section 2 roll-up: FAIL if any blocking, unwaived FAIL (a Waived status
    only counts when the finding is waivable); else UNKNOWN if any blocking UNKNOWN;
    else PASS. INFO never counts. Empty input -> UNKNOWN."""
    if not reviewed:
        return Verdict.UNKNOWN
    if any(_is_blocking_fail(r) for r in reviewed):
        return Verdict.FAIL
    if any(r.finding.result is Verdict.UNKNOWN and r.finding.blocking for r in reviewed):
        return Verdict.UNKNOWN
    return Verdict.PASS


def count_line(reviewed: Sequence[ReviewedFinding]) -> tuple[int, int, int]:
    """(blocking, unknown, passed) counts for the VERDICT line."""
    blocking = sum(1 for r in reviewed if _is_blocking_fail(r))
    unknown = sum(1 for r in reviewed if r.finding.result is Verdict.UNKNOWN)
    passed = sum(1 for r in reviewed if r.finding.result is Verdict.PASS)
    return blocking, unknown, passed


def ascii_safe(text: str) -> str:
    """Replace every non-ASCII char with '?'."""
    return "".join(c if ord(c) < 128 else "?" for c in text)


def render_finding(item: ReviewedFinding) -> list[str]:
    """Lines for one finding (ARCHITECTURE.md 4.13)."""
    f = item.finding
    path = f.normalized_path + (f":{f.line}" if f.line is not None else "")
    evidence = f.source_file_or_log
    if f.source_line_or_offset:
        evidence += f" @ {f.source_line_or_offset}"
    lines = [
        f"{f.result.value} {f.rule_id} | {f.message}",
        f"  path: {path}",
        f"  observed: {f.observed_value} | expected: {f.expected_value}",
        f"  evidence: {evidence} | sha256: {f.source_sha256 or '-'}",
    ]
    if item.status is not WorkflowStatus.NONE:
        status = f"  status: {item.status.value}"
        if item.reason:
            status += f" | reason: {item.reason}"
        if item.reviewer:
            status += f" | reviewer: {item.reviewer}"
        if item.reviewed_at:
            status += f" | date: {item.reviewed_at}"
        if item.reopened:
            status += " (reopened)"
        lines.append(status)
    if f.cache_state is CacheState.CACHED:
        date = item.verified_on or f.checked_at_utc[:10]
        lines.append(VERIFIED_FORMAT.format(date=date))
    return lines


def render_text(report: Report, *, show_pass: bool = False) -> str:
    """Full stdout/.txt text (ARCHITECTURE.md section 8)."""
    out: list[str] = [HEADER_FORMAT.format(profile=report.profile_id, release=report.release_id)]
    if report.verdict is None:
        out.append("VERDICT: n/a")
    else:
        blocking, unknown, passed = count_line(report.findings)
        out.append(VERDICT_FORMAT.format(verdict=report.verdict.value, blocking=blocking,
                                         unknown=unknown, passed=passed))
    out.append(f"Reason: {report.reason}")
    out.append(COUNTS_FORMAT.format(cached=report.cached, rechecked=report.rechecked))
    if report.body_lines:
        out.append("")
        out.extend(report.body_lines)
    order = [Verdict.FAIL, Verdict.UNKNOWN, Verdict.INFO] + ([Verdict.PASS] if show_pass else [])
    shown = [r for v in order for r in report.findings if r.finding.result is v]
    if shown:
        out.append("")
        for item in shown:
            out.extend(render_finding(item))
            out.append("")
        out.pop()
    if report.text_path:
        out.append("")
        out.append(f"Full report: {report.text_path}")
    return ascii_safe(chr(10).join(out) + chr(10))


def _plain(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {f.name: _plain(getattr(value, f.name)) for f in dataclasses.fields(value)}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _plain(v) for k, v in value.items()}
    return value


def render_json(report: Report) -> str:
    """JSON of the whole report (every Finding field + status fields)."""
    return json.dumps(_plain(report), indent=2, sort_keys=True, ensure_ascii=True)


def write_report(report: Report, reports_dir: Path, stamp: str, *, show_pass: bool = False) -> Report:
    """Write '<reports_dir>/<stamp>_<command>.txt' and '.json'; return the report
    with text_path/json_path set."""
    reports_dir.mkdir(parents=True, exist_ok=True)
    name = f"{stamp}_{report.command.replace(' ', '-')}"
    txt, js = reports_dir / f"{name}.txt", reports_dir / f"{name}.json"
    out = dataclasses.replace(report, text_path=txt.as_posix(), json_path=js.as_posix())
    txt.write_text(render_text(out, show_pass=show_pass), encoding="ascii", newline=chr(10))
    js.write_text(render_json(out), encoding="ascii", newline=chr(10))
    return out


def emit(text: str, stream: TextIO) -> None:
    """The ONLY console writer in the package: ascii_safe(text) + trailing newline."""
    stream.write(ascii_safe(text.rstrip(chr(10))) + chr(10))
    stream.flush()


def emit_prompt(text: str, stream: TextIO) -> None:
    """Write an interactive prompt (no trailing newline) through the same single writer module."""
    stream.write(ascii_safe(text))
    stream.flush()


def findings_only(reviewed: Sequence[ReviewedFinding]) -> list[Finding]:
    """[r.finding for r in reviewed]."""
    return [r.finding for r in reviewed]
