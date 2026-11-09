"""Unit: dependency fingerprint, cache reuse, workflow status."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from gso_checker import memory
from gso_checker.config import load_rules
from gso_checker.model import (CacheState, Finding, ReviewDecision, Verdict, WorkflowStatus)
from gso_checker.store import Store
from tests.helpers import PROFILE, RULES_PATH


@pytest.fixture(scope="module")
def rule():
    return load_rules(RULES_PATH)["V04"]


def make(fp: str, result: Verdict = Verdict.FAIL, src: str = "s" * 64) -> Finding:
    return Finding("fid1", "V04", PROFILE, "R1", "a.nut", None, result, "msg", "o", "e",
                   "R1.zip!a.nut", None, src, "1", "2026-11-08T01:02:03Z", fp, waivable=True)


def test_fingerprint_deterministic_and_sensitive(rule) -> None:
    base = memory.dependency_fingerprint(rule, PROFILE, {"release": "a", "repo": "b"})
    assert base == memory.dependency_fingerprint(rule, PROFILE, {"repo": "b", "release": "a"})
    assert len(base) == 64
    assert base != memory.dependency_fingerprint(rule, PROFILE, {"release": "a", "repo": "c"})
    assert base != memory.dependency_fingerprint(rule, "other", {"release": "a", "repo": "b"})
    bumped = dataclasses.replace(rule, version="2")
    assert base != memory.dependency_fingerprint(bumped, PROFILE, {"release": "a", "repo": "b"})


def test_set_fingerprint_order_free() -> None:
    assert memory.set_fingerprint(["b", "a", "a"]) == memory.set_fingerprint(["a", "b"])


def test_cache_key_format() -> None:
    assert memory.cache_key("V04", PROFILE, "R1", "Script/A.nut") == "V04|EUREX-1.5|R1|script/a.nut"


def test_evaluate_cached_reuses_then_rechecks(tmp_path: Path, rule) -> None:
    store = Store(tmp_path / "c.db")
    calls: list[str] = []

    def ev(fp: str) -> list[Finding]:
        calls.append(fp)
        return [make(fp)]

    try:
        one = memory.evaluate_cached(store, rule, PROFILE, "R1", "a.nut", {"release": "a"}, ev)
        two = memory.evaluate_cached(store, rule, PROFILE, "R1", "a.nut", {"release": "a"}, ev)
        three = memory.evaluate_cached(store, rule, PROFILE, "R1", "a.nut", {"release": "CHANGED"}, ev)
        assert len(calls) == 2
        assert one[0].cache_state is CacheState.RECHECKED
        assert two[0].cache_state is CacheState.CACHED
        assert two[0].checked_at_utc == one[0].checked_at_utc
        assert three[0].cache_state is CacheState.RECHECKED
        assert three[0].dependency_fingerprint != one[0].dependency_fingerprint
        bumped = dataclasses.replace(rule, version="2")
        memory.evaluate_cached(store, bumped, PROFILE, "R1", "a.nut", {"release": "CHANGED"}, ev)
        assert len(calls) == 3
    finally:
        store.close()


def decision(status: WorkflowStatus, fp: str, reason: str = "r") -> ReviewDecision:
    return ReviewDecision("fid1", "s" * 64, "1", fp, status, reason, "BB1", "2026-11-08T00:00:00Z", "x.csv")


def test_workflow_status_rules(tmp_path: Path) -> None:
    store = Store(tmp_path / "c.db")
    try:
        assert memory.workflow_status(make("fp1"), store).status is WorkflowStatus.OPEN
        assert memory.workflow_status(make("fp1", Verdict.PASS), store).status is WorkflowStatus.NONE

        store.add_decision(decision(WorkflowStatus.FIXED, "fp1"))
        assert memory.workflow_status(make("fp1"), store).status is WorkflowStatus.FIXED
        assert memory.workflow_status(make("fp2", Verdict.PASS), store).status is WorkflowStatus.FIXED
        r = memory.workflow_status(make("fp2"), store)
        assert r.status is WorkflowStatus.OPEN and r.reopened is True

        store.add_decision(decision(WorkflowStatus.WAIVED, "fp1", reason="author approved"))
        w = memory.workflow_status(make("fp1"), store)
        assert w.status is WorkflowStatus.WAIVED and w.reason == "author approved"
        assert w.reviewer == "BB1" and w.reviewed_at == "2026-11-08T00:00:00Z"
        assert w.finding.result is Verdict.FAIL
        x = memory.workflow_status(make("fp9"), store)
        assert x.status is WorkflowStatus.OPEN and x.reopened is True
        assert memory.active_waiver_ids([w, x]) == {"fid1"}
    finally:
        store.close()


def test_verified_on_only_when_cached(tmp_path: Path) -> None:
    store = Store(tmp_path / "c.db")
    try:
        f = make("fp1")
        assert memory.workflow_status(f, store).verified_on is None
        c = dataclasses.replace(f, cache_state=CacheState.CACHED)
        assert memory.workflow_status(c, store).verified_on == "2026-11-08"
    finally:
        store.close()
