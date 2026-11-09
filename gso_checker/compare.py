"""Comparisons and version rules V01, V04, V05, V06 plus the phase-1 orchestrators.

Contract: ARCHITECTURE.md 4.4 (rules) and 4.11 (orchestrators).
"""

from __future__ import annotations

import dataclasses
import logging
import re
import zipfile
from dataclasses import dataclass
from functools import lru_cache
from typing import Callable, Mapping, Sequence

from gso_checker import hashing, history, manifest, memory
from gso_checker.config import Config, is_gso_owned, release_by_id, rule_applies
from gso_checker.model import (CacheState, Classification, CheckerError, ComparisonRow, ConfigError,
                               Finding, Manifest, ManifestEntry, Packaging, Report, RuleSpec, Verdict,
                               _utcnow, make_finding_id, utc_iso)
from gso_checker.store import Store

logger = logging.getLogger(__name__)

UNINSTALL_SCRIPT: str = "GSO_Uninstall.bat"
ORIGINALS_PREFIX: str = "GSO/originals/"
GAME_SCOPE_PREFIX: str = "@game/"


@dataclass(frozen=True)
class UninstallPlan:
    """Static reading of GSO_Uninstall.bat."""

    restores: dict[str, str]          # dst path_key -> src normalized path (e.g. 'GSO/originals/TATW.cfg')
    removes: tuple[str, ...]          # normalized paths deleted (del) or removed (rmdir)
    understood: bool                  # False if any line is outside the known grammar
    unparsed_lines: tuple[str, ...]


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------

def _src(m: Manifest, e: ManifestEntry) -> str:
    """Evidence string for a manifest entry."""
    if e.archive_member:
        return f"{m.source_path}!{e.archive_member}"
    return f"{m.source_path}/{e.normalized_path}"


def _make(rule: RuleSpec, profile_id: str, input_id: str, path: str, result: Verdict, message: str,
          observed: str, expected: str, source: str, source_sha: str | None, checked_at: str,
          fingerprint: str, *, blocking: bool | None = None) -> Finding:
    if blocking is None:
        blocking = result in (Verdict.FAIL, Verdict.UNKNOWN)
    return Finding(
        finding_id=make_finding_id(rule.id, profile_id, input_id, path, None),
        rule_id=rule.id, profile_id=profile_id, input_id=input_id, normalized_path=path, line=None,
        result=result, message=message, observed_value=observed, expected_value=expected,
        source_file_or_log=source, source_line_or_offset=None, source_sha256=source_sha,
        rule_version=rule.version, checked_at_utc=checked_at, dependency_fingerprint=fingerprint,
        blocking=blocking, waivable=bool(rule.waivable), cache_state=CacheState.RECHECKED)


def _fmt(rule: RuleSpec, **fields: str) -> str:
    try:
        return rule.message.format(**fields)
    except (KeyError, IndexError, ValueError):
        return fields.get("path", "") + ": " + " ".join(v for k, v in fields.items() if k != "path")


def compare_manifests(a: Manifest, b: Manifest) -> list[ComparisonRow]:
    """Union of both manifests' keys, one row per key, classified with
    hashing.classify; a_label = a.release_id, b_label = b.release_id.
    Sorted by normalized_path.casefold(). Row path spelling: A's if present else B's."""
    ai, bi = manifest.by_key(a), manifest.by_key(b)
    rows: list[ComparisonRow] = []
    for key in sorted(set(ai) | set(bi)):
        ea, eb = ai.get(key), bi.get(key)
        first = ea if ea is not None else eb
        assert first is not None
        rows.append(ComparisonRow(
            normalized_path=first.normalized_path,
            classification=hashing.classify(ea, eb),
            a_label=a.release_id, b_label=b.release_id,
            a_sha256=ea.sha256 if ea else None, b_sha256=eb.sha256 if eb else None,
            a_size=ea.size if ea else None, b_size=eb.size if eb else None))
    return rows


# --------------------------------------------------------------------------
# V01
# --------------------------------------------------------------------------

_V01_WORDING: dict[Classification, str] = {
    Classification.IDENTICAL: "identical",
    Classification.ONLY_A: "missing from release",
    Classification.DIFFERENT: "different",
    Classification.LINE_ENDINGS: "different (line endings only)",
}


def _v01(repo: Manifest, release: Manifest, repo_e: ManifestEntry, rel_e: ManifestEntry | None,
         rule: RuleSpec, checked_at: str, fp: str) -> Finding:
    cls = hashing.classify(repo_e, rel_e)
    path = repo_e.normalized_path
    result = Verdict.PASS if cls is Classification.IDENTICAL else Verdict.FAIL
    wording = _V01_WORDING.get(cls, cls.value)
    if rel_e is None:
        observed, source, source_sha = "absent", _src(repo, repo_e), repo_e.sha256
    else:
        observed, source, source_sha = rel_e.sha256, _src(release, rel_e), rel_e.sha256
    return _make(rule, release.profile_id, release.release_id, path, result,
                 _fmt(rule, path=path, classification=wording), observed, repo_e.sha256,
                 source, source_sha, checked_at, fp)


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
    key = path_key.casefold()
    repo_e = manifest.by_key(repo).get(key)
    if repo_e is None:
        return []
    return [_v01(repo, release, repo_e, manifest.by_key(release).get(key), rule, checked_at_utc,
                 fingerprint)]


# --------------------------------------------------------------------------
# V04
# --------------------------------------------------------------------------

def _v04(release: Manifest, repo_e: ManifestEntry, rel_e: ManifestEntry | None,
         past: Sequence[tuple[str, str, str]], rule: RuleSpec, checked_at: str,
         fp: str) -> list[Finding]:
    if rel_e is None:
        return []
    path = repo_e.normalized_path
    if rel_e.sha256 == repo_e.sha256:
        result, wording = Verdict.PASS, "identical to repo"
    else:
        result, wording = Verdict.FAIL, "different from repo"
        match = [h for h in past if h[1] == rel_e.sha256]
        if match:
            snap, _sha, recorded = match[-1]
            wording = f"older than repo: equals repo snapshot {snap} recorded {recorded[:10]}"
    return [_make(rule, release.profile_id, release.release_id, path, result,
                  _fmt(rule, path=path, wording=wording), rel_e.sha256, repo_e.sha256,
                  _src(release, rel_e), rel_e.sha256, checked_at, fp)]


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
    key = path_key.casefold()
    repo_e = manifest.by_key(repo).get(key)
    if repo_e is None:
        return []
    return _v04(release, repo_e, manifest.by_key(release).get(key), history.get(key, []),
                rule, checked_at_utc, fingerprint)


# --------------------------------------------------------------------------
# V05
# --------------------------------------------------------------------------

def rule_v05(live: Manifest, repo: Manifest, known_path_keys: set[str], cfg: Config,
             rule: RuleSpec, checked_at_utc: str, fingerprint: str) -> list[Finding]:
    """Untracked live files inside GSO-owned globs only.

    For each live entry with config.is_gso_owned(path) True whose key is in
    neither repo nor known_path_keys: one finding, result FAIL if
    cfg.block_extras else INFO (blocking False), message contains
    'live, not in repo, not in any manifest', observed_value = live sha256,
    source_sha256 = live sha256, input_id 'live'. Files outside owned globs
    are never reported. No PASS findings."""
    repo_keys = {e.normalized_path.casefold() for e in repo.entries}
    known = {k.casefold() for k in known_path_keys}
    result = Verdict.FAIL if cfg.block_extras else Verdict.INFO
    out: list[Finding] = []
    for e in live.entries:
        key = e.normalized_path.casefold()
        if not is_gso_owned(cfg, e.normalized_path) or key in repo_keys or key in known:
            continue
        out.append(_make(rule, cfg.profile_id, "live", e.normalized_path, result,
                         _fmt(rule, path=e.normalized_path), e.sha256,
                         "file present in repo or in a stored manifest", _src(live, e), e.sha256,
                         checked_at_utc, fingerprint, blocking=result is Verdict.FAIL))
    return out


# --------------------------------------------------------------------------
# GSO_Uninstall.bat
# --------------------------------------------------------------------------

_I = re.IGNORECASE
_RE_IGNORED = re.compile(r"^(@echo\s+off|echo(\s.*)?|echo\.|rem(\s.*)?|::.*|pushd\s.*|popd|setlocal.*|"
                         r"endlocal.*|pause|exit(\s.*)?)$", _I)
_RE_COPY = re.compile(r'^copy\s+/y\s+"([^"]+)"\s+"([^"]+)"(\s+>\s*nul)?$', _I)
_RE_IF_DEL = re.compile(r'^if\s+exist\s+"([^"]+)"\s+del\s+/f\s+/q\s+"([^"]+)"$', _I)
_RE_DEL = re.compile(r'^del\s+/f\s+/q\s+"([^"]+)"$', _I)
_RE_IF_RMDIR = re.compile(r'^if\s+exist\s+"([^"]+)"\s+rmdir\s+/s\s+/q\s+"([^"]+)"$', _I)
_RE_RMDIR = re.compile(r'^rmdir\s+/s\s+/q\s+"([^"]+)"$', _I)
_RE_PAUSE_Q = re.compile(r'^if\s+/i\s+not\s+"%1"=="-q"\s+pause$', _I)
_RE_SELF_DELETE = re.compile(r'^\(goto\)\s+2>nul\s+&\s+del\s+/f\s+/q\s+"%~f0"$', _I)


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
    restores: dict[str, str] = {}
    removes: list[str] = []
    unparsed: list[str] = []

    def norm(p: str) -> str:
        return p.replace("\\", "/")

    for raw in text.splitlines():
        line = raw.strip()
        if not line or _RE_IGNORED.match(line) or _RE_PAUSE_Q.match(line) or _RE_SELF_DELETE.match(line):
            continue
        m = _RE_COPY.match(line)
        if m:
            restores[norm(m.group(2)).casefold()] = norm(m.group(1))
            continue
        m = _RE_IF_DEL.match(line) or _RE_IF_RMDIR.match(line)
        if m and m.group(1).casefold() == m.group(2).casefold():
            removes.append(norm(m.group(2)))
            continue
        m = _RE_DEL.match(line) or _RE_RMDIR.match(line)
        if m:
            removes.append(norm(m.group(1)))
            continue
        unparsed.append(line)
    return UninstallPlan(restores, tuple(removes), not unparsed, tuple(unparsed))


@lru_cache(maxsize=8)
def _plan(text: str) -> UninstallPlan:
    return parse_uninstall_plan(text)


# --------------------------------------------------------------------------
# V06
# --------------------------------------------------------------------------

def _v06(release: Manifest, rel_e: ManifestEntry, rel_idx: Mapping[str, ManifestEntry],
         base_e: ManifestEntry | None, baseline_configured: bool,
         backup_shas: set[str], uninstall_text: str | None, rule: RuleSpec, checked_at: str,
         fp: str) -> Finding:
    path = rel_e.normalized_path
    key = path.casefold()
    profile, rid = release.profile_id, release.release_id
    src = _src(release, rel_e)

    def mk(result: Verdict, state: str, observed: str, expected: str,
           blocking: bool | None = None) -> Finding:
        return _make(rule, profile, rid, path, result, _fmt(rule, path=path, state=state),
                     observed, expected, src, rel_e.sha256, checked_at, fp, blocking=blocking)

    if not baseline_configured:
        return mk(Verdict.UNKNOWN, "EUR baseline not configured", "baseline: not configured",
                  "original EUR file preserved and restored by uninstall")
    if base_e is None:
        return mk(Verdict.INFO, "new file outside GSO-owned paths; not an EUR replacement",
                  rel_e.sha256, "absent from EUR baseline", blocking=False)
    orig = base_e.sha256
    problems: list[str] = []
    hard = False
    if orig not in backup_shas:
        problems.append("original not saved in backup")
        hard = True
    if uninstall_text is None:
        problems.append("GSO_Uninstall.bat not in release")
        hard = True
    else:
        plan = _plan(uninstall_text)
        src_path = plan.restores.get(key)
        src_e = rel_idx.get(src_path.casefold()) if src_path else None
        if not (src_e is not None and src_e.sha256 == orig):
            if plan.understood:
                problems.append("uninstall does not restore original")
                hard = True
            else:
                problems.append("uninstall behavior not established statically")
    if not problems:
        return mk(Verdict.PASS, "EUR original saved in backup and restored by uninstall",
                  rel_e.sha256, orig)
    return mk(Verdict.FAIL if hard else Verdict.UNKNOWN, "; ".join(problems), rel_e.sha256, orig)


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
    key = path_key.casefold()
    rel_idx = manifest.by_key(release)
    rel_e = rel_idx.get(key)
    if rel_e is None:
        return []
    base_e = manifest.by_key(baseline).get(key) if baseline is not None else None
    backup_shas = {e.sha256 for b in backups for e in b.entries if e.normalized_path.casefold() == key}
    return [_v06(release, rel_e, rel_idx, base_e, baseline is not None, backup_shas, uninstall_text,
                 rule, checked_at_utc, fingerprint)]


# --------------------------------------------------------------------------
# orchestrators
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class VersionCheckResult:
    release: Manifest
    repo: Manifest
    rows: tuple[ComparisonRow, ...]
    findings: tuple[Finding, ...]      # V01..V07, after cache handling
    cached: int
    rechecked: int


def _chain_ids(cfg: Config, release_id: str) -> list[str]:
    """release_id plus its patch parents (only PATCH releases compose)."""
    ids = [release_id]
    spec = release_by_id(cfg, release_id)
    while spec.packaging is Packaging.PATCH and spec.parent and spec.parent not in ids:
        ids.append(spec.parent)
        spec = release_by_id(cfg, spec.parent)
    return ids


def _ordered_manifests(cfg: Config, release_id: str, store: Store, rules: Mapping[str, RuleSpec],
                       cache: dict[str, Manifest]) -> list[tuple[int, Manifest]]:
    """Composed manifests of every same-profile release up to and including the target,
    oldest first, each recorded (immutably) in the store."""
    target_spec = release_by_id(cfg, release_id)
    out: list[tuple[int, Manifest]] = []
    for spec in cfg.releases:
        if spec.profile_id != cfg.profile_id or spec.order > target_spec.order:
            continue
        try:
            m = manifest.composed_manifest(cfg, spec.release_id, rules, cache)
        except (CheckerError, OSError, zipfile.BadZipFile) as exc:
            if spec.release_id == release_id:
                raise
            logger.warning("release %s skipped for history: %s", spec.release_id, exc)
            continue
        store.record_manifest(m, packaging=spec.packaging.value,
                              packaging_root=spec.packaging_root.value, parent=spec.parent,
                              ordinal=spec.order)
        out.append((spec.order, m))
    return out


def run_version_checks(cfg: Config, release_id: str, store: Store,
                       rules: Mapping[str, RuleSpec], *, include_live: bool = True,
                       command: str = "check") -> VersionCheckResult:
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
    `command` only labels the stored findings run ('check' or 'compare').
    """
    now = utc_iso(_utcnow())
    profile = cfg.profile_id
    spec = release_by_id(cfg, release_id)
    repo = manifest.build_overlay_manifest(cfg)
    findings: list[Finding] = []
    counts = {"cached": 0, "rechecked": 0}

    def run_unit(rule: RuleSpec, unit: str, inputs: Mapping[str, str],
                 fn: Callable[[str], list[Finding]]) -> None:
        got = memory.evaluate_cached(store, rule, profile, release_id, unit, inputs, fn)
        for f in got:
            counts["cached" if f.cache_state is CacheState.CACHED else "rechecked"] += 1
        findings.extend(got)

    def finish(release: Manifest) -> VersionCheckResult:
        run_id = utc_iso(_utcnow()).replace("-", "").replace(":", "") + "-" + command
        store.record_findings(run_id, command, findings)
        return VersionCheckResult(release, repo, tuple(compare_manifests(repo, release)),
                                  tuple(findings), counts["cached"], counts["rechecked"])

    if spec.profile_id != profile:
        v02 = rules.get("V02")
        if v02 is None:
            raise ConfigError("rule V02 missing from the rules catalog")
        fp = memory.dependency_fingerprint(v02, profile, {"release_profile": spec.profile_id})
        findings.append(_make(
            v02, profile, release_id, "", Verdict.UNKNOWN,
            f"{release_id}: profile mismatch ({spec.profile_id} is not the checked profile {profile})",
            spec.profile_id, profile, str(spec.path), spec.sha256, now, fp))
        counts["rechecked"] += 1
        return finish(Manifest(release_id, spec.profile_id, "release", str(spec.path), spec.sha256, ()))

    history.record_repo_snapshot(store, repo)
    cache: dict[str, Manifest] = {}
    ordered = _ordered_manifests(cfg, release_id, store, rules, cache)
    target = cache[release_id]
    rel_idx = manifest.by_key(target)
    repo_idx = manifest.by_key(repo)

    # ---- V02 / V07 (whole release)
    chain = _chain_ids(cfg, release_id)
    zip_inputs = ({"zip": target.source_sha256 or "absent"} if len(chain) == 1 else
                  {f"zip:{cid}": (cache[cid].source_sha256 or "absent") for cid in chain if cid in cache})
    for rid in ("V02", "V07"):
        rule = rules.get(rid)
        if rule is None or not rule_applies(rule, profile):
            continue
        run_unit(rule, "", zip_inputs,
                 lambda fp, rid=rid: [dataclasses.replace(f, dependency_fingerprint=fp)
                                      for f in target.problems if f.rule_id == rid])

    # ---- V01 / V04 (per repo path)
    v01, v04 = rules.get("V01"), rules.get("V04")
    hist = history.repo_history(store, profile, repo.release_id)
    for key, repo_e in repo_idx.items():
        rel_e = rel_idx.get(key)
        base_inputs = {"release": rel_e.sha256 if rel_e else "absent", "repo": repo_e.sha256}
        if v01 is not None and rule_applies(v01, profile):
            inputs = dict(base_inputs,
                          release_eol=(rel_e.eol_sha256 if rel_e and rel_e.eol_sha256 else "absent"),
                          repo_eol=repo_e.eol_sha256 or "absent")
            run_unit(v01, key, inputs,
                     lambda fp, re_=repo_e, rl=rel_e, r=v01: [_v01(repo, target, re_, rl, r, now, fp)])
        if v04 is not None and rule_applies(v04, profile):
            past = hist.get(key, [])
            inputs = dict(base_inputs, history=memory.set_fingerprint([h[1] for h in past]))
            run_unit(v04, key, inputs,
                     lambda fp, re_=repo_e, rl=rel_e, p=past, r=v04: _v04(target, re_, rl, p, r, now, fp))

    # ---- V03 (per path over ordered manifests)
    v03 = rules.get("V03")
    if v03 is not None and rule_applies(v03, profile):
        idxs = [(order, m, manifest.by_key(m)) for order, m in ordered]
        grouped: dict[str, list[Finding]] = {}
        computed = [False]

        def aba_for(key: str, fp: str) -> list[Finding]:
            if not computed[0]:
                for f in history.rule_v03([m for _o, m in ordered], v03, now):
                    grouped.setdefault(f.normalized_path.casefold(), []).append(f)
                computed[0] = True
            return [dataclasses.replace(f, dependency_fingerprint=fp) for f in grouped.get(key, [])]

        for key in rel_idx:
            seq = [f"{order}:{m.release_id}:{ix[key].sha256}" for order, m, ix in idxs if key in ix]
            run_unit(v03, key, {"seq": memory.set_fingerprint(seq)}, lambda fp, k=key: aba_for(k, fp))

    # ---- V05 (live, untracked owned files)
    v05 = rules.get("V05")
    if include_live and v05 is not None and rule_applies(v05, profile):
        if not cfg.live_mod.is_dir():
            run_unit(v05, "", {"live": "absent"},
                     lambda fp: [_make(v05, profile, "live", "", Verdict.UNKNOWN,
                                       f"live mod folder not found: {cfg.live_mod}", "absent",
                                       "live mod folder present", str(cfg.live_mod), None, now, fp)])
        else:
            live = manifest.build_tree_manifest(
                cfg.live_mod, release_id="live", kind="live", profile_id=profile,
                text_extensions=cfg.text_extensions, include=lambda p: is_gso_owned(cfg, p))
            known = store.known_path_keys(profile, ("release", "repo", "baseline", "backup"))
            inputs = {
                "live": memory.set_fingerprint([f"{e.normalized_path.casefold()}:{e.sha256}"
                                                for e in live.entries]),
                "repo_keys": memory.set_fingerprint(list(repo_idx)),
                "known_keys": memory.set_fingerprint(sorted(known)),
            }
            run_unit(v05, "", inputs, lambda fp: rule_v05(live, repo, known, cfg, v05, now, fp))

    # ---- V06 (EUR-owned replacement, per candidate path)
    v06 = rules.get("V06")
    if v06 is not None and rule_applies(v06, profile):
        cands = [e for e in target.entries
                 if not is_gso_owned(cfg, e.normalized_path)
                 and not e.normalized_path.startswith(GAME_SCOPE_PREFIX)]
        cand_keys = {e.normalized_path.casefold() for e in cands}
        baseline: Manifest | None = None
        if cfg.eur_baseline is not None and cfg.eur_baseline.is_dir():
            baseline = manifest.build_tree_manifest(
                cfg.eur_baseline, release_id="baseline", kind="baseline", profile_id=profile,
                text_extensions=cfg.text_extensions, include=lambda p: p.casefold() in cand_keys)
        base_idx = manifest.by_key(baseline) if baseline is not None else {}
        backup_by_key: dict[str, set[str]] = {}
        for b in manifest.load_backup_manifests(cfg):
            for e in b.entries:
                backup_by_key.setdefault(e.normalized_path.casefold(), set()).add(e.sha256)
        bat = rel_idx.get(UNINSTALL_SCRIPT.casefold())
        uninstall_text: str | None = None
        if bat is not None:
            uninstall_text = manifest.read_release_bytes(
                cfg, release_id, bat.normalized_path).decode("latin-1")
        for e in cands:
            key = e.normalized_path.casefold()
            base_e = base_idx.get(key)
            orig_src = rel_idx.get((ORIGINALS_PREFIX + e.normalized_path).casefold())
            shas = backup_by_key.get(key, set())
            inputs = {
                "release": e.sha256,
                "baseline": ("not configured" if baseline is None
                             else (base_e.sha256 if base_e else "absent")),
                "backups": memory.set_fingerprint([f"{key}:{s}" for s in shas]),
                "uninstall": bat.sha256 if bat is not None else "absent",
                "original_src": orig_src.sha256 if orig_src is not None else "absent",
            }
            run_unit(v06, key, inputs,
                     lambda fp, e=e, be=base_e, sh=shas: [_v06(
                         target, e, rel_idx, be, baseline is not None, sh, uninstall_text,
                         v06, now, fp)])

    order_of = {"V02": 0, "V07": 1, "V01": 2, "V04": 3, "V03": 4, "V05": 5, "V06": 6}
    findings.sort(key=lambda f: (order_of.get(f.rule_id, 9), f.normalized_path.casefold()))
    return finish(target)


# --------------------------------------------------------------------------
# reports
# --------------------------------------------------------------------------

def _reason(verdict: Verdict, findings: Sequence[Finding]) -> str:
    bad = [f for f in findings if f.result is verdict]
    rule_ids = ", ".join(sorted({f.rule_id for f in bad}))
    if verdict is Verdict.PASS:
        return "Every checked rule passed."
    if verdict is Verdict.FAIL:
        return f"The release has {len(bad)} failing finding(s) under {rule_ids}."
    return f"{len(bad)} finding(s) under {rule_ids} could not be established."


def _build_report(command: str, cfg: Config, release_id: str, store: Store,
                  findings: Sequence[Finding], body: Sequence[str]) -> Report:
    from gso_checker import report as report_mod  # imported late: report is built separately

    reviewed = tuple(memory.workflow_status(f, store) for f in findings)
    verdict = report_mod.rollup(reviewed)
    cached = sum(1 for f in findings if f.cache_state is CacheState.CACHED)
    return Report(command=command, profile_id=cfg.profile_id, release_id=release_id,
                  verdict=verdict, reason=_reason(verdict, findings), findings=reviewed,
                  cached=cached, rechecked=len(findings) - cached, body_lines=tuple(body),
                  exit_code={Verdict.PASS: 0, Verdict.FAIL: 1}.get(verdict, 2))


def run_compare(cfg: Config, release_id: str, store: Store,
                rules: Mapping[str, RuleSpec]) -> Report:
    """`compare`: repo vs composed release vs live (owned paths).

    body_lines: one line per non-identical row:
      '<classification> | <path> | repo <sha|-> | release <sha|-> | live <sha|->'
    (live column '-' when cfg.live_mod is missing or the path is not owned/present).
    findings: V01 and V04 for the release (via run_version_checks with
    include_live=False). verdict = report.rollup of those findings.
    """
    res = run_version_checks(cfg, release_id, store, rules, include_live=False, command="compare")
    body: list[str] = []
    live_dir = cfg.live_mod if cfg.live_mod.is_dir() else None
    for row in res.rows:
        if row.classification is Classification.IDENTICAL:
            continue
        live_sha = "-"
        if live_dir is not None and is_gso_owned(cfg, row.normalized_path):
            target = live_dir / row.normalized_path
            if target.is_file():
                try:
                    live_sha = hashing.sha256_file(target)
                except OSError as exc:
                    logger.warning("cannot hash live file %s: %s", target, exc)
        body.append(f"{row.classification.value} | {row.normalized_path} | repo {row.a_sha256 or '-'} | "
                    f"release {row.b_sha256 or '-'} | live {live_sha}")
    keep = [f for f in res.findings if f.rule_id in ("V01", "V04")]
    return _build_report("compare", cfg, release_id, store, keep, body)


def run_check(cfg: Config, release_id: str, store: Store,
              rules: Mapping[str, RuleSpec]) -> Report:
    """`check` (phase 1 = version rules only): run_version_checks, attach
    workflow status (memory.workflow_status), roll up, build the Report."""
    res = run_version_checks(cfg, release_id, store, rules, include_live=True, command="check")
    return _build_report("check", cfg, release_id, store, res.findings, ())
