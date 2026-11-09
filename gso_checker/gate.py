"""install-gate: ALWAYS read-only (no writes under game_root, ever).

Contract: ARCHITECTURE.md 4.10.
"""

from __future__ import annotations

import logging
from pathlib import Path, PurePosixPath
from typing import Mapping, Sequence

from gso_checker import model
from gso_checker.compare import run_version_checks
from gso_checker.config import Config, release_by_id
from gso_checker.manifest import GAME_SCOPE_PREFIX
from gso_checker.model import (Finding, GateCheck, GateDecision, GateOutcome, Manifest,
                               ProcessInfo, ProcessObservation, ProcessState, Report, RuleSpec,
                               Verdict, Waiver)
from gso_checker.process import ProcessProbe
from gso_checker.store import Store

logger = logging.getLogger(__name__)

CHECK_ORDER: tuple[str, ...] = ("profile", "process", "manifest", "backup", "mapping", "waivers")

# Rules whose FAIL may be closed by a valid waiver for installation.
WAIVABLE_RULES: frozenset[str] = frozenset({"V01", "V03", "V04", "V05"})

_MANIFEST_RULES: frozenset[str] = frozenset({"V01", "V02", "V03", "V04", "V05", "V07"})


def _check(name: str, verdict: Verdict, reason: str, *, waivable: bool = False,
           waived: bool = False, finding_ids: Sequence[str] = ()) -> GateCheck:
    return GateCheck(name, verdict, reason, waivable, waived, tuple(finding_ids))


def _inside(root: Path, target: Path) -> bool:
    """True when resolved `target` is `root` or below it (case-insensitive)."""
    try:
        r = [p.casefold() for p in root.resolve().parts]
        t = [p.casefold() for p in target.resolve().parts]
    except (OSError, RuntimeError) as exc:
        logger.warning("cannot resolve %s / %s: %s", root, target, exc)
        return False
    return len(t) >= len(r) and t[:len(r)] == r


def check_profile(cfg: Config, release_profile: str) -> GateCheck:
    """PASS only if release_profile == cfg.profile_id == cfg.game_profile ==
    cfg.eur_baseline_profile, cfg.eur_baseline is configured and exists, and
    game_root/game_exe exists. Any missing proof -> UNKNOWN (names what is
    missing); a mismatch -> FAIL naming both values. Not waivable."""
    mismatches: list[str] = []
    missing: list[str] = []
    if release_profile != cfg.profile_id:
        mismatches.append(f"release profile {release_profile!r} != checker profile {cfg.profile_id!r}")
    if not cfg.game_profile:
        missing.append("game profile not declared")
    elif cfg.game_profile != cfg.profile_id:
        mismatches.append(f"game profile {cfg.game_profile!r} != checker profile {cfg.profile_id!r}")
    if not cfg.eur_baseline_profile:
        missing.append("EUR baseline profile not declared")
    elif cfg.eur_baseline_profile != cfg.profile_id:
        mismatches.append(
            f"EUR baseline profile {cfg.eur_baseline_profile!r} != checker profile {cfg.profile_id!r}")
    if cfg.eur_baseline is None:
        missing.append("EUR baseline not configured")
    elif not cfg.eur_baseline.exists():
        missing.append(f"EUR baseline path does not exist: {cfg.eur_baseline}")
    exe = cfg.game_root / cfg.game_exe
    if not exe.is_file():
        missing.append(f"game executable not found: {exe}")
    if mismatches:
        return _check("profile", Verdict.FAIL, "; ".join(mismatches + missing))
    if missing:
        return _check("profile", Verdict.UNKNOWN, "profile proof missing: " + "; ".join(missing))
    return _check("profile", Verdict.PASS,
                  f"release, checker, game and EUR baseline all declare {cfg.profile_id}; game exe present")


def check_process(cfg: Config, probe: ProcessProbe) -> tuple[GateCheck, ProcessObservation]:
    """Call probe(cfg.process_names). RUNNING -> FAIL with image, PID, path and
    observed_at in the reason; UNKNOWN -> UNKNOWN 'process state could not be
    determined'; NOT_RUNNING -> PASS (reason includes method and time).
    Returns (check, ProcessObservation). Not waivable."""
    try:
        observed = probe(cfg.process_names)
    except Exception as exc:  # noqa: BLE001 - any probe failure means "cannot determine"
        logger.warning("process probe raised: %s", exc)
        observed = ProcessObservation(ProcessState.UNKNOWN, (), model.utc_iso(model._utcnow()),
                                      "probe", f"probe failed: {exc}")
    if observed.state is ProcessState.RUNNING:
        def one(p: ProcessInfo) -> str:
            return f"{p.image} PID {p.pid} path {p.path or 'unavailable'}"
        procs = "; ".join(one(p) for p in observed.processes) or "process details unavailable"
        return (_check("process", Verdict.FAIL,
                       f"game is running: {procs}; observed {observed.observed_at_utc} via {observed.method}"),
                observed)
    if observed.state is ProcessState.NOT_RUNNING:
        return (_check("process", Verdict.PASS,
                       f"game not running; observed {observed.observed_at_utc} via {observed.method}"),
                observed)
    detail = f" ({observed.detail})" if observed.detail else ""
    return (_check("process", Verdict.UNKNOWN,
                   f"process state could not be determined{detail}; observed "
                   f"{observed.observed_at_utc} via {observed.method}"), observed)


def check_manifest(findings: Sequence[Finding], waivers: Sequence[Waiver]) -> GateCheck:
    """FAIL/UNKNOWN findings of V01-V05 and V07 (V06 belongs to 'backup').
    A FAIL of a WAIVABLE_RULES rule is closed when a waiver with that
    finding_id and a non-empty reason exists (waived=True). V02/V07 FAIL and
    every UNKNOWN are never waivable. Reason lists each open finding as
    '<rule_id> <normalized_path>'. finding_ids = open findings."""
    valid = {w.finding_id for w in waivers if w.reason.strip() and w.author.strip()}
    open_fail: list[Finding] = []
    open_unknown: list[Finding] = []
    waived: list[Finding] = []
    for f in findings:
        if f.rule_id not in _MANIFEST_RULES:
            continue
        if f.result is Verdict.FAIL:
            if f.rule_id in WAIVABLE_RULES and f.finding_id in valid:
                waived.append(f)
            else:
                open_fail.append(f)
        elif f.result is Verdict.UNKNOWN:
            open_unknown.append(f)

    def label(f: Finding) -> str:
        return f"{f.rule_id} {f.normalized_path or '(whole release)'}"

    waivable_open = any(f.rule_id in WAIVABLE_RULES for f in open_fail)
    if open_fail or open_unknown:
        verdict = Verdict.FAIL if open_fail else Verdict.UNKNOWN
        opened = open_fail + open_unknown
        reason = "open findings: " + "; ".join(label(f) for f in opened)
        return _check("manifest", verdict, reason, waivable=waivable_open,
                      finding_ids=[f.finding_id for f in opened])
    if waived:
        return _check("manifest", Verdict.PASS,
                      "closed by waiver: " + "; ".join(label(f) for f in waived),
                      waivable=True, waived=True, finding_ids=[f.finding_id for f in waived])
    return _check("manifest", Verdict.PASS, "composed release matches the required repository files")


def check_backup(cfg: Config, findings: Sequence[Finding]) -> GateCheck:
    """PASS needs: cfg.backups configured, exists, is a directory, is NOT inside
    cfg.game_root (resolved paths), and every V06 finding PASS or INFO.
    Any V06 UNKNOWN -> UNKNOWN naming 'V06 <path>'; any V06 FAIL -> FAIL.
    Not waivable."""
    fails: list[str] = []
    unknowns: list[str] = []
    ids: list[str] = []
    if cfg.backups is None:
        fails.append("backups folder not configured")
    elif not cfg.backups.is_dir():
        fails.append(f"backups folder does not exist: {cfg.backups}")
    elif _inside(cfg.game_root, cfg.backups):
        fails.append(f"backups folder is inside the game folder: {cfg.backups}")
    for f in findings:
        if f.rule_id != "V06":
            continue
        if f.result is Verdict.FAIL:
            fails.append(f"V06 {f.normalized_path}")
            ids.append(f.finding_id)
        elif f.result is Verdict.UNKNOWN:
            unknowns.append(f"V06 {f.normalized_path}")
            ids.append(f.finding_id)
    if fails:
        return _check("backup", Verdict.FAIL, "; ".join(fails + unknowns), finding_ids=ids)
    if unknowns:
        return _check("backup", Verdict.UNKNOWN, "cannot prove EUR originals are preserved: "
                      + "; ".join(unknowns), finding_ids=ids)
    return _check("backup", Verdict.PASS, "backups folder usable; every EUR original is preserved")


def _bad_relative(path: str) -> bool:
    if not path or path.startswith("/") or "\\" in path or ":" in path.split("/")[0]:
        return True
    return any(seg in ("", ".", "..") for seg in path.split("/")) or not PurePosixPath(path).parts


def check_mapping(cfg: Config, release: Manifest) -> GateCheck:
    """PASS when every entry resolves inside cfg.live_mod (no '@game/' entry,
    no path escape, no case collision in release.problems) and cfg.live_mod is
    inside cfg.game_root. Otherwise FAIL naming the entries. Not waivable."""
    bad: list[str] = []
    if not _inside(cfg.game_root, cfg.live_mod):
        bad.append(f"live mod folder {cfg.live_mod} is not inside game folder {cfg.game_root}")
    seen: dict[str, str] = {}
    for e in release.entries:
        p = e.normalized_path
        if p.startswith(GAME_SCOPE_PREFIX):
            bad.append(f"{p} (game-root file, not installable)")
            continue
        if _bad_relative(p) or not _inside(cfg.live_mod, cfg.live_mod / p):
            bad.append(f"{p} (resolves outside the mod folder)")
            continue
        k = p.casefold()
        if k in seen:
            bad.append(f"{p} (ambiguous: same destination as {seen[k]})")
        seen[k] = p
    for f in release.problems:
        if f.rule_id == "V07" and f.result is Verdict.FAIL:
            bad.append(f"V07 {f.normalized_path or '(whole release)'}")
    if bad:
        return _check("mapping", Verdict.FAIL, "unsafe destination mapping: " + "; ".join(bad))
    return _check("mapping", Verdict.PASS,
                  f"all {len(release.entries)} files map inside {cfg.live_mod}")


def check_waivers(waivers: Sequence[Waiver]) -> GateCheck:
    """FAIL if any waiver has an empty/whitespace reason or empty author
    ('waiver for <finding_id> has no reason'); else PASS."""
    problems: list[str] = []
    for w in waivers:
        if not w.reason.strip():
            problems.append(f"waiver for {w.finding_id} has no reason")
        elif not w.author.strip():
            problems.append(f"waiver for {w.finding_id} has no author")
    if problems:
        return _check("waivers", Verdict.FAIL, "; ".join(problems),
                      finding_ids=[w.finding_id for w in waivers])
    return _check("waivers", Verdict.PASS, f"{len(waivers)} waiver(s), all with reason and author")


def evaluate_gate(cfg: Config, release_id: str, *, probe: ProcessProbe, store: Store,
                  rules: Mapping[str, RuleSpec], waivers: Sequence[Waiver] = ()) -> GateDecision:
    """Run run_version_checks(include_live=True) then the six checks in
    CHECK_ORDER. outcome ALLOW only if every check is PASS (a waivable FAIL
    closed by waivers counts as PASS). GateDecision.findings = every finding
    of that version-check run (results unchanged by waivers). Store writes are limited to the normal
    findings/manifests/cache of the version-check run (data_dir, never the
    game folder). Report files are written by the CLI under cfg.reports_dir.
    Writes nothing under cfg.game_root."""
    spec = release_by_id(cfg, release_id)
    result = run_version_checks(cfg, release_id, store, rules, include_live=True)
    findings = tuple(result.findings)
    process_check, observed = check_process(cfg, probe)
    by_name = {
        "profile": check_profile(cfg, spec.profile_id),
        "process": process_check,
        "manifest": check_manifest(findings, waivers),
        "backup": check_backup(cfg, findings),
        "mapping": check_mapping(cfg, result.release),
        "waivers": check_waivers(waivers),
    }
    checks = tuple(by_name[n] for n in CHECK_ORDER)
    allow = all(c.verdict is Verdict.PASS for c in checks)
    return GateDecision(release_id, cfg.profile_id, GateOutcome.ALLOW if allow else GateOutcome.REFUSE,
                        checks, findings, observed, model.utc_iso(model._utcnow()))


def gate_report(decision: GateDecision) -> Report:
    """Report with verdict PASS for ALLOW else FAIL, reason = first non-PASS
    check reason (or 'All install prerequisites passed.'), body_lines:
    'DECISION: ALLOW|REFUSE' then one line per check
    '<VERDICT> <name> | <reason>' (+ ' [waived]'), exit_code 0 ALLOW / 3 REFUSE."""
    allow = decision.outcome is GateOutcome.ALLOW
    first = next((c for c in decision.checks if c.verdict is not Verdict.PASS), None)
    reason = "All install prerequisites passed." if first is None else f"{first.name}: {first.reason}"
    lines = [f"DECISION: {decision.outcome.value}"]
    for c in decision.checks:
        lines.append(f"{c.verdict.value} {c.name} | {c.reason}" + (" [waived]" if c.waived else ""))
    return Report("install-gate", decision.profile_id, decision.release_id,
                  Verdict.PASS if allow else Verdict.FAIL, reason, (), 0, 0, tuple(lines),
                  0 if allow else 3)
