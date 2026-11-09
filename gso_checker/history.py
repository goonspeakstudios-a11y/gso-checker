"""Release history: V03 A-B-A detection and repo-snapshot history for V04.

Contract: ARCHITECTURE.md 4.5.
"""

from __future__ import annotations

import logging
from typing import Sequence

from gso_checker.model import AbaHit, Finding, Manifest, RuleSpec
from gso_checker.store import Store

logger = logging.getLogger(__name__)


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
    raise NotImplementedError


def rule_v03(manifests: Sequence[Manifest], rule: RuleSpec, checked_at_utc: str) -> list[Finding]:
    """One V03 FAIL Finding per AbaHit (no PASS rows).

    input_id = last release id; normalized_path = hit path;
    message contains the three release ids in order first, middle, last;
    observed_value = '<first_id>:<sha> -> <middle_id>:<sha> -> <last_id>:<sha>';
    expected_value = 'no return to an older hash after a change';
    source_sha256 = last sha; dependency_fingerprint is set by memory.evaluate_cached.
    """
    raise NotImplementedError


def record_repo_snapshot(store: Store, repo: Manifest) -> bool:
    """Store the repo overlay manifest (kind='repo') if not already stored.
    Returns True if newly recorded."""
    raise NotImplementedError


def repo_history(store: Store, profile_id: str, exclude_release_id: str) -> dict[str, list[tuple[str, str, str]]]:
    """{path_key: [(snapshot_release_id, sha256, recorded_at_utc), ...]} over all
    stored kind='repo' manifests of the profile except `exclude_release_id`
    (the current snapshot), oldest first."""
    raise NotImplementedError
