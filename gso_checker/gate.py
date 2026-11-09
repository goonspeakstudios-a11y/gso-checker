"""install-gate: ALWAYS read-only (no writes under game_root, ever).

Contract: ARCHITECTURE.md 4.10.
"""

from __future__ import annotations

import logging
from typing import Mapping, Sequence

from gso_checker.config import Config
from gso_checker.model import (Finding, GateCheck, GateDecision, Manifest, ProcessObservation,
                               Report, RuleSpec, Waiver)
from gso_checker.process import ProcessProbe
from gso_checker.store import Store

logger = logging.getLogger(__name__)

CHECK_ORDER: tuple[str, ...] = ("profile", "process", "manifest", "backup", "mapping", "waivers")

# Rules whose FAIL may be closed by a valid waiver for installation.
WAIVABLE_RULES: frozenset[str] = frozenset({"V01", "V03", "V04", "V05"})


def check_profile(cfg: Config, release_profile: str) -> GateCheck:
    """PASS only if release_profile == cfg.profile_id == cfg.game_profile ==
    cfg.eur_baseline_profile, cfg.eur_baseline is configured and exists, and
    game_root/game_exe exists. Any missing proof -> UNKNOWN (names what is
    missing); a mismatch -> FAIL naming both values. Not waivable."""
    raise NotImplementedError


def check_process(cfg: Config, probe: ProcessProbe) -> tuple[GateCheck, ProcessObservation]:
    """Call probe(cfg.process_names). RUNNING -> FAIL with image, PID, path and
    observed_at in the reason; UNKNOWN -> UNKNOWN 'process state could not be
    determined'; NOT_RUNNING -> PASS (reason includes method and time).
    Returns (check, ProcessObservation). Not waivable."""
    raise NotImplementedError


def check_manifest(findings: Sequence[Finding], waivers: Sequence[Waiver]) -> GateCheck:
    """FAIL/UNKNOWN findings of V01-V05 and V07 (V06 belongs to 'backup').
    A FAIL of a WAIVABLE_RULES rule is closed when a waiver with that
    finding_id and a non-empty reason exists (waived=True). V02/V07 FAIL and
    every UNKNOWN are never waivable. Reason lists each open finding as
    '<rule_id> <normalized_path>'. finding_ids = open findings."""
    raise NotImplementedError


def check_backup(cfg: Config, findings: Sequence[Finding]) -> GateCheck:
    """PASS needs: cfg.backups configured, exists, is a directory, is NOT inside
    cfg.game_root (resolved paths), and every V06 finding PASS or INFO.
    Any V06 UNKNOWN -> UNKNOWN naming 'V06 <path>'; any V06 FAIL -> FAIL.
    Not waivable."""
    raise NotImplementedError


def check_mapping(cfg: Config, release: Manifest) -> GateCheck:
    """PASS when every entry resolves inside cfg.live_mod (no '@game/' entry,
    no path escape, no case collision in release.problems) and cfg.live_mod is
    inside cfg.game_root. Otherwise FAIL naming the entries. Not waivable."""
    raise NotImplementedError


def check_waivers(waivers: Sequence[Waiver]) -> GateCheck:
    """FAIL if any waiver has an empty/whitespace reason or empty author
    ('waiver for <finding_id> has no reason'); else PASS."""
    raise NotImplementedError


def evaluate_gate(cfg: Config, release_id: str, *, probe: ProcessProbe, store: Store,
                  rules: Mapping[str, RuleSpec], waivers: Sequence[Waiver] = ()) -> GateDecision:
    """Run run_version_checks(include_live=True) then the six checks in
    CHECK_ORDER. outcome ALLOW only if every check is PASS (a waivable FAIL
    closed by waivers counts as PASS). GateDecision.findings = every finding
    of that version-check run (results unchanged by waivers). Store writes are limited to the normal
    findings/manifests/cache of the version-check run (data_dir, never the
    game folder). Report files are written by the CLI under cfg.reports_dir.
    Writes nothing under cfg.game_root."""
    raise NotImplementedError


def gate_report(decision: GateDecision) -> Report:
    """Report with verdict PASS for ALLOW else FAIL, reason = first non-PASS
    check reason (or 'All install prerequisites passed.'), body_lines:
    'DECISION: ALLOW|REFUSE' then one line per check
    '<VERDICT> <name> | <reason>' (+ ' [waived]'), exit_code 0 ALLOW / 3 REFUSE."""
    raise NotImplementedError
