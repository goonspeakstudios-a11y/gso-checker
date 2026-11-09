"""Verification memory: dependency fingerprints, cache reuse, workflow status.

Contract: ARCHITECTURE.md 4.7 and section 6.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
from typing import Callable, Mapping, Sequence

from gso_checker import model
from gso_checker.model import (CacheState, Finding, ReviewedFinding, RuleSpec, Verdict,
                               WorkflowStatus)
from gso_checker.store import Store

logger = logging.getLogger(__name__)


def dependency_fingerprint(rule: RuleSpec, profile_id: str, inputs: Mapping[str, str]) -> str:
    """sha256 hex of the canonical JSON
    {"rule_id": rule.id, "rule_version": rule.version, "profile_id": profile_id,
     "inputs": [[name, value], ...] sorted by name}
    encoded with json.dumps(..., sort_keys=True, separators=(',', ':')).
    `inputs` values are sha256 strings, 'absent', or fingerprints of sets."""
    payload = {
        "rule_id": rule.id,
        "rule_version": rule.version,
        "profile_id": profile_id,
        "inputs": [[k, inputs[k]] for k in sorted(inputs)],
    }
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def set_fingerprint(values: Sequence[str]) -> str:
    """sha256 hex over '\\n'.join(sorted(set(values))). Used for path-key sets
    and hash sets inside `inputs`."""
    return hashlib.sha256("\n".join(sorted(set(values))).encode("utf-8")).hexdigest()


def cache_key(rule_id: str, profile_id: str, input_id: str, unit: str) -> str:
    """f"{rule_id}|{profile_id}|{input_id}|{unit.casefold()}" (unit = normalized
    path, or '' for whole-input rules)."""
    return f"{rule_id}|{profile_id}|{input_id}|{unit.casefold()}"


def evaluate_cached(store: Store, rule: RuleSpec, profile_id: str, input_id: str, unit: str,
                    inputs: Mapping[str, str],
                    evaluate: Callable[[str], list[Finding]]) -> list[Finding]:
    """Reuse or recompute one evaluation unit.

    A cached result is reused only if rule id (in the key), rule version, profile
    (in the key) and dependency fingerprint are all unchanged. Inputs are always
    freshly hashed by the caller; the cache never skips hashing.
    """
    fp = dependency_fingerprint(rule, profile_id, inputs)
    key = cache_key(rule.id, profile_id, input_id, unit)
    hit = store.get_cache(key)
    if hit is not None:
        version, cached_fp, findings, _verified = hit
        if version == rule.version and cached_fp == fp:
            return [dataclasses.replace(f, cache_state=CacheState.CACHED) for f in findings]
    fresh = [dataclasses.replace(f, cache_state=CacheState.RECHECKED) for f in evaluate(fp)]
    store.put_cache(key, rule.id, rule.version, profile_id, fp, fresh,
                    model.utc_iso(model._utcnow()))
    return fresh


def workflow_status(finding: Finding, store: Store) -> ReviewedFinding:
    """Combine a finding with the latest human decision (never alters finding.result)."""
    verified = finding.checked_at_utc[:10] if finding.cache_state is CacheState.CACHED else None
    open_default = (WorkflowStatus.OPEN
                    if finding.result in (Verdict.FAIL, Verdict.UNKNOWN) else WorkflowStatus.NONE)
    d = store.latest_decision(finding.finding_id)
    if d is None:
        return ReviewedFinding(finding, open_default, verified_on=verified)
    valid = (d.rule_version == finding.rule_version
             and d.dependency_fingerprint == finding.dependency_fingerprint)
    failing = finding.result in (Verdict.FAIL, Verdict.UNKNOWN)

    def kept(status: WorkflowStatus) -> ReviewedFinding:
        return ReviewedFinding(finding, status, d.reason, d.reviewer, d.reviewed_at,
                               verified_on=verified)

    if d.status is WorkflowStatus.OPEN:
        return ReviewedFinding(finding, WorkflowStatus.OPEN, d.reason, d.reviewer, d.reviewed_at,
                               verified_on=verified)
    if d.status is WorkflowStatus.FIXED:
        if not failing or valid:
            return kept(WorkflowStatus.FIXED)
        return ReviewedFinding(finding, WorkflowStatus.OPEN, "fixed, but the rule fails again "
                               "after the input changed", reopened=True, verified_on=verified)
    if d.status in (WorkflowStatus.WAIVED, WorkflowStatus.NOT_A_BUG, WorkflowStatus.ENGINE):
        if valid:
            return kept(d.status)
        return ReviewedFinding(finding, WorkflowStatus.OPEN,
                               "waiver expired: input or rule changed", reopened=True,
                               verified_on=verified)
    return ReviewedFinding(finding, open_default, verified_on=verified)


def active_waiver_ids(reviewed: Sequence[ReviewedFinding]) -> set[str]:
    """finding_ids whose status is WAIVED (valid waivers only)."""
    return {r.finding.finding_id for r in reviewed if r.status is WorkflowStatus.WAIVED}
