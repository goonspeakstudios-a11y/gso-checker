"""Release history: V03 A-B-A detection and repo-snapshot history for V04.

Contract: ARCHITECTURE.md 4.5.
"""

from __future__ import annotations

import logging
from typing import Sequence

from gso_checker.model import (AbaHit, CacheState, Finding, ImmutableRecordError, Manifest,
                               RuleSpec, Verdict, make_finding_id)
from gso_checker.store import Store

logger = logging.getLogger(__name__)

ABA_EXPECTED: str = "no return to an older hash after a change"


def find_aba(manifests: Sequence[Manifest]) -> list[AbaHit]:
    """A-B-A detection over manifests given OLDEST FIRST.

    Manifests are grouped by profile_id (order kept inside each group); no
    comparison ever crosses profiles. For each group and each path key
    (normalized_path.casefold()), take the sequence S of (release_id, sha256)
    over the manifests that CONTAIN the path (absent releases are skipped, not
    treated as a differing hash). For every index n >= 2 in S: if
    S[n].sha != S[n-1].sha and some k < n-1 has S[k].sha == S[n].sha, emit
    AbaHit(first=S[k_max], middle=S[n-1], last=S[n]) where k_max is the largest
    such k. normalized_path uses the spelling in S[n]'s manifest.
    Result sorted by (profile_id, path key, last release order).
    """
    # (profile, key) -> [(release order, release_id, sha, spelling)]
    seqs: dict[tuple[str, str], list[tuple[int, str, str, str]]] = {}
    for order, m in enumerate(manifests):
        for e in m.entries:
            seqs.setdefault((m.profile_id, e.normalized_path.casefold()), []).append(
                (order, m.release_id, e.sha256, e.normalized_path))
    found: list[tuple[str, str, int, AbaHit]] = []
    for (profile, key), seq in seqs.items():
        for n in range(2, len(seq)):
            if seq[n][2] == seq[n - 1][2]:
                continue
            k_max = next((k for k in range(n - 2, -1, -1) if seq[k][2] == seq[n][2]), None)
            if k_max is None:
                continue
            hit = AbaHit(profile_id=profile, normalized_path=seq[n][3],
                         first=(seq[k_max][1], seq[k_max][2]),
                         middle=(seq[n - 1][1], seq[n - 1][2]),
                         last=(seq[n][1], seq[n][2]))
            found.append((profile, key, seq[n][0], hit))
    found.sort(key=lambda t: (t[0], t[1], t[2]))
    return [t[3] for t in found]


def rule_v03(manifests: Sequence[Manifest], rule: RuleSpec, checked_at_utc: str,
             fingerprint: str = "") -> list[Finding]:
    """One V03 FAIL Finding per AbaHit (no PASS rows).

    input_id = last release id; normalized_path = hit path;
    message contains the three release ids in order first, middle, last;
    observed_value = '<first_id>:<sha> -> <middle_id>:<sha> -> <last_id>:<sha>';
    expected_value = 'no return to an older hash after a change';
    source_sha256 = last sha; dependency_fingerprint is set by memory.evaluate_cached
    (callers pass `fingerprint`; default empty).
    """
    sources = {m.release_id: m.source_path for m in manifests}
    out: list[Finding] = []
    for h in find_aba(manifests):
        message = rule.message.format(path=h.normalized_path, first=h.first[0],
                                      middle=h.middle[0], last=h.last[0])
        observed = " -> ".join(f"{rid}:{sha}" for rid, sha in (h.first, h.middle, h.last))
        out.append(Finding(
            finding_id=make_finding_id(rule.id, h.profile_id, h.last[0], h.normalized_path, None),
            rule_id=rule.id, profile_id=h.profile_id, input_id=h.last[0],
            normalized_path=h.normalized_path, line=None, result=Verdict.FAIL, message=message,
            observed_value=observed, expected_value=ABA_EXPECTED,
            source_file_or_log=sources.get(h.last[0], ""), source_line_or_offset=None,
            source_sha256=h.last[1], rule_version=rule.version, checked_at_utc=checked_at_utc,
            dependency_fingerprint=fingerprint, blocking=True, waivable=bool(rule.waivable),
            cache_state=CacheState.RECHECKED))
    return out


def record_repo_snapshot(store: Store, repo: Manifest) -> bool:
    """Store the repo overlay manifest (kind='repo') if not already stored.
    Returns True if newly recorded."""
    if store.get_manifest(repo.release_id) is not None:
        return False
    ordinal = len(store.list_manifests(repo.profile_id, "repo"))
    try:
        return store.record_manifest(repo, ordinal=ordinal)
    except ImmutableRecordError as exc:
        logger.warning("repo snapshot %s not recorded: %s", repo.release_id, exc)
        return False


def repo_history(store: Store, profile_id: str, exclude_release_id: str) -> dict[str, list[tuple[str, str, str]]]:
    """{path_key: [(snapshot_release_id, sha256, recorded_at_utc), ...]} over all
    stored kind='repo' manifests of the profile except `exclude_release_id`
    (the current snapshot), oldest first."""
    # Manifest carries no recorded_at; read it straight from the releases table.
    rows = store._db.execute(  # noqa: SLF001
        "SELECT release_id, recorded_at_utc FROM releases WHERE profile_id=? AND kind='repo'",
        (profile_id,)).fetchall()
    stamps = {r["release_id"]: r["recorded_at_utc"] for r in rows}
    out: dict[str, list[tuple[str, str, str]]] = {}
    for m in store.list_manifests(profile_id, "repo"):
        if m.release_id == exclude_release_id:
            continue
        for e in m.entries:
            out.setdefault(e.normalized_path.casefold(), []).append(
                (m.release_id, e.sha256, stamps.get(m.release_id, "")))
    return out
