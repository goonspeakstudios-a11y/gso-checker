"""Comparisons and version rules V01, V04, V05, V06 plus the phase-1 orchestrators.

Contract: ARCHITECTURE.md 4.4 (rules) and 4.11 (orchestrators).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Mapping, Sequence

from gso_checker.config import Config
from gso_checker.model import ComparisonRow, Finding, Manifest, Report, RuleSpec
from gso_checker.store import Store

logger = logging.getLogger(__name__)

UNINSTALL_SCRIPT: str = "GSO_Uninstall.bat"
ORIGINALS_PREFIX: str = "GSO/originals/"


@dataclass(frozen=True)
class UninstallPlan:
    """Static reading of GSO_Uninstall.bat."""

    restores: dict[str, str]          # dst path_key -> src normalized path (e.g. 'GSO/originals/TATW.cfg')
    removes: tuple[str, ...]          # normalized paths deleted (del) or removed (rmdir)
    understood: bool                  # False if any line is outside the known grammar
    unparsed_lines: tuple[str, ...]


def compare_manifests(a: Manifest, b: Manifest) -> list[ComparisonRow]:
    """Union of both manifests' keys, one row per key, classified with
    hashing.classify; a_label = a.release_id, b_label = b.release_id.
    Sorted by normalized_path.casefold(). Row path spelling: A's if present else B's."""
    raise NotImplementedError


def rule_v01(repo: Manifest, release: Manifest, rule: RuleSpec, checked_at_utc: str,
             fingerprint: str, path_key: str) -> list[Finding]:
    """V01 for ONE required repo path key (returns exactly 1 finding).

    Every repo entry is required (repo_not_installed were already excluded when
    the overlay manifest was built). Classification via hashing.classify(repo, release):
    IDENTICAL -> PASS; ONLY_A (missing from release) -> FAIL 'missing from release';
    DIFFERENT -> FAIL; LINE_ENDINGS -> FAIL with message mentioning 'line endings only'.
    Release-only files produce no V01 finding. input_id = release.release_id;
    observed_value = release sha256 or 'absent'; expected_value = repo sha256;
    source_sha256 = release sha256 (repo sha256 when absent from release);
    source_file_or_log = '<release.source_path>!<archive_member>' or the repo path."""
    raise NotImplementedError


def rule_v04(repo: Manifest, release: Manifest, history: Mapping[str, list[tuple[str, str, str]]],
             rule: RuleSpec, checked_at_utc: str, fingerprint: str, path_key: str) -> list[Finding]:
    """Stale-versus-repo for ONE path key present in repo (returns 0 or 1 finding).

    Release absent -> no finding (V01 covers it). Same sha256 -> PASS.
    Different: if history[path_key] has an entry with sha256 == release sha256 ->
    FAIL, message contains "older than repo: equals repo snapshot <snapshot_id>
    recorded <date>"; otherwise FAIL with message containing "different from repo"
    and NOT the word "older". Never uses ZIP timestamps.
    observed_value = release sha256; expected_value = repo sha256;
    source_sha256 = release sha256."""
    raise NotImplementedError


def rule_v05(live: Manifest, repo: Manifest, known_path_keys: set[str], cfg: Config,
             rule: RuleSpec, checked_at_utc: str, fingerprint: str) -> list[Finding]:
    """Untracked live files inside GSO-owned globs only.

    For each live entry with config.is_gso_owned(path) True whose key is in
    neither repo nor known_path_keys: one finding, result FAIL if
    cfg.block_extras else INFO (blocking False), message contains
    'live, not in repo, not in any manifest', observed_value = live sha256,
    source_sha256 = live sha256, input_id 'live'. Files outside owned globs
    are never reported. No PASS findings."""
    raise NotImplementedError


def parse_uninstall_plan(text: str) -> UninstallPlan:
    """Parse GSO_Uninstall.bat (case-insensitive, lines stripped, '\\' -> '/').

    Known grammar (anything else -> understood False, line kept in unparsed_lines):
      blank | '@echo off' | 'echo ...' | 'rem ...' | '::...' | 'pushd ...' | 'popd'
      | 'setlocal' | 'endlocal' | 'pause' | 'exit ...'
      | 'copy /y "SRC" "DST"' [' >nul']            -> restores[DST.casefold()] = SRC
      | 'if exist "P" del /f /q "P"'                 -> removes += P
      | 'del /f /q "P"'                               -> removes += P
      | 'if exist "P" rmdir /s /q "P"' | 'rmdir /s /q "P"' -> removes += P
      | 'if /i not "%1"=="-q" pause'
      | '(goto) 2>nul & del /f /q "%~f0"'          (self-delete idiom)
    """
    raise NotImplementedError


def rule_v06(release: Manifest, baseline: Manifest | None, backups: Sequence[Manifest],
             uninstall_text: str | None, cfg: Config, rule: RuleSpec, checked_at_utc: str,
             fingerprint: str, path_key: str) -> list[Finding]:
    """EUR-original preservation for ONE candidate path key.

    Candidates (chosen by the caller): release entries that are not GSO-owned
    (config.is_gso_owned False) and not '@game/' scoped.
      baseline None -> UNKNOWN, message contains 'EUR baseline not configured',
                       observed_value 'baseline: not configured'.
      path absent from baseline -> INFO (blocking False) 'new file outside
                       GSO-owned paths; not an EUR replacement'.
      else orig = baseline sha256;
        saved   := some backup manifest has this key with sha256 == orig;
        plan    := parse_uninstall_plan(uninstall_text) (uninstall_text None -> FAIL
                   'GSO_Uninstall.bat not in release');
        restorable := key in plan.restores and the release has
                   plan.restores[key] with sha256 == orig.
        Problems are collected separately, in this order, and joined with '; '
        into ONE finding (one finding per path keeps finding_id stable):
          not saved                        -> 'original not saved in backup'
          not restorable, plan.understood  -> 'uninstall does not restore original'
          not restorable, not understood   -> 'uninstall behavior not established statically'
        any of the first two -> FAIL; only the third -> UNKNOWN; none -> PASS.
    observed/expected carry the shas; source_sha256 = release sha256."""
    raise NotImplementedError


@dataclass(frozen=True)
class VersionCheckResult:
    release: Manifest
    repo: Manifest
    rows: tuple[ComparisonRow, ...]
    findings: tuple[Finding, ...]      # V01..V07, after cache handling
    cached: int
    rechecked: int


def run_version_checks(cfg: Config, release_id: str, store: Store,
                       rules: Mapping[str, RuleSpec], *, include_live: bool = True) -> VersionCheckResult:
    """Phase-1 `check`: V01-V07 for one release (ARCHITECTURE.md 4.11).

    Steps: build repo manifest + record_repo_snapshot; compose every configured
    release of cfg.profile_id (record_manifest each, ordinal = order); V02/V07
    from the target's composed problems (unit ''); V01 and V04 (unit per repo path),
    V03 (unit per path over the ordered same-profile manifests up to and
    including the target), V05 (unit '', live tree limited to owned globs,
    skipped with one UNKNOWN finding when live_mod is missing), V06 (unit per
    candidate path). Every unit goes through memory.evaluate_cached with the
    inputs listed in ARCHITECTURE.md section 6. Releases of another profile
    than cfg.profile_id -> one UNKNOWN finding (rule V02, message 'profile
    mismatch') and no other rule runs. Records findings in the store.
    """
    raise NotImplementedError


def run_compare(cfg: Config, release_id: str, store: Store,
                rules: Mapping[str, RuleSpec]) -> Report:
    """`compare`: repo vs composed release vs live (owned paths).

    body_lines: one line per non-identical row:
      '<classification> | <path> | repo <sha|-> | release <sha|-> | live <sha|->'
    (live column '-' when cfg.live_mod is missing or the path is not owned/present).
    findings: V01 and V04 for the release (via run_version_checks with
    include_live=False). verdict = report.rollup of those findings.
    """
    raise NotImplementedError


def run_check(cfg: Config, release_id: str, store: Store,
              rules: Mapping[str, RuleSpec]) -> Report:
    """`check` (phase 1 = version rules only): run_version_checks, attach
    workflow status (memory.workflow_status), roll up, build the Report."""
    raise NotImplementedError
