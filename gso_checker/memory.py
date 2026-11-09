"""Verification memory: dependency fingerprints, cache reuse, workflow status.

Contract: ARCHITECTURE.md 4.7 and section 6.
"""

from __future__ import annotations

import logging
from typing import Callable, Mapping, Sequence

from gso_checker.model import Finding, ReviewedFinding, RuleSpec
from gso_checker.store import Store

logger = logging.getLogger(__name__)


def dependency_fingerprint(rule: RuleSpec, profile_id: str, inputs: Mapping[str, str]) -> str:
    """sha256 hex of the canonical JSON
    {"rule_id": rule.id, "rule_version": rule.version, "profile_id": profile_id,
     "inputs": [[name, value], ...] sorted by name}
    encoded with json.dumps(..., sort_keys=True, separators=(',', ':')).
    `inputs` values are sha256 strings, 'absent', or fingerprints of sets."""
    raise NotImplementedError


def set_fingerprint(values: Sequence[str]) -> str:
    """sha256 hex over '\\n'.join(sorted(set(values))). Used for path-key sets
    and hash sets inside `inputs`."""
    raise NotImplementedError


def cache_key(rule_id: str, profile_id: str, input_id: str, unit: str) -> str:
    """f"{rule_id}|{profile_id}|{input_id}|{unit.casefold()}" (unit = normalized
    path, or '' for whole-input rules)."""
    raise NotImplementedError


def evaluate_cached(store: Store, rule: RuleSpec, profile_id: str, input_id: str, unit: str,
                    inputs: Mapping[str, str],
                    evaluate: Callable[[str], list[Finding]]) -> list[Finding]:
    """Reuse or recompute one evaluation unit.

    fp = dependency_fingerprint(rule, profile_id, inputs). If store.get_cache(key)
    exists with the same rule.version and fp, return its findings with
    cache_state=CACHED (all other fields unchanged, including checked_at_utc).
    Otherwise call evaluate(fp) -- which must stamp dependency_fingerprint=fp
    on every Finding it returns -- set cache_state=RECHECKED, store with
    put_cache (verified_at_utc = now) and return them.
    Note: inputs are always freshly hashed by the caller; the cache never skips
    hashing.
    """
    raise NotImplementedError


def workflow_status(finding: Finding, store: Store) -> ReviewedFinding:
    """Combine a finding with the latest human decision (never alters finding.result).

    No decision: OPEN for FAIL/UNKNOWN, NONE for PASS/INFO.
    'still valid' := decision.rule_version == finding.rule_version and
                     decision.dependency_fingerprint == finding.dependency_fingerprint.
    FIXED:   finding PASS/INFO -> FIXED; FAIL/UNKNOWN and still valid -> FIXED;
             FAIL/UNKNOWN and not still valid -> OPEN with reopened=True.
    WAIVED:  still valid -> WAIVED (reason/reviewer/reviewed_at kept);
             not still valid -> OPEN, reopened=True, reason
             'waiver expired: input or rule changed'.
    NOT_A_BUG / ENGINE: same validity rule as WAIVED.
    OPEN decision -> OPEN.
    verified_on = finding.checked_at_utc[:10] ('YYYY-MM-DD', the date of the
    original evaluation) when finding.cache_state is CACHED, else None.
    """
    raise NotImplementedError


def active_waiver_ids(reviewed: Sequence[ReviewedFinding]) -> set[str]:
    """finding_ids whose status is WAIVED (valid waivers only)."""
    raise NotImplementedError
