"""Unit: compare_manifests, V01, V04 wording ('different' vs 'older'), uninstall-plan parsing."""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from gso_checker import compare, history
from gso_checker.config import load_rules
from gso_checker.model import Classification, Manifest, ManifestEntry, Verdict
from gso_checker.store import Store
from tests.helpers import MOD, PROFILE, REL_054E, RULES_PATH, UNINSTALL_BAT, require, sha

TEXT = (".nut", ".txt")
NOW = "2026-11-08T00:00:00Z"


def man(rid: str, files: dict[str, bytes], kind: str = "release") -> Manifest:
    def eol(p: str, d: bytes) -> str | None:
        return sha(d.replace(b"\r\n", b"\n")) if p.endswith(TEXT) else None
    return Manifest(rid, PROFILE, kind, f"{rid}.zip", None, tuple(
        ManifestEntry(rid, PROFILE, p, len(d), sha(d), eol(p, d), p, rid) for p, d in sorted(files.items())))


@pytest.fixture(scope="module")
def rules() -> dict:
    return load_rules(RULES_PATH)


def test_compare_manifests_rows() -> None:
    a = man("repo@x", {"same.nut": b"1", "diff.nut": b"1", "eol.nut": b"a\r\n", "onlya.nut": b"1"}, "repo")
    b = man("R1", {"same.nut": b"1", "diff.nut": b"2", "eol.nut": b"a\n", "onlyb.nut": b"1"})
    rows = {r.normalized_path: r.classification for r in compare.compare_manifests(a, b)}
    assert rows == {"diff.nut": Classification.DIFFERENT, "eol.nut": Classification.LINE_ENDINGS,
                    "onlya.nut": Classification.ONLY_A, "onlyb.nut": Classification.ONLY_B,
                    "same.nut": Classification.IDENTICAL}


def test_v01_missing_and_line_endings_fail(rules: dict) -> None:
    repo = man("repo@x", {"a.nut": b"x\r\n", "b.nut": b"b", "c.nut": b"c"}, "repo")
    rel = man("R1", {"a.nut": b"x\n", "c.nut": b"c"})
    a = compare.rule_v01(repo, rel, rules["V01"], NOW, "fp", "a.nut")
    b = compare.rule_v01(repo, rel, rules["V01"], NOW, "fp", "b.nut")
    c = compare.rule_v01(repo, rel, rules["V01"], NOW, "fp", "c.nut")
    assert a[0].result is Verdict.FAIL and "line endings only" in a[0].message
    assert b[0].result is Verdict.FAIL and b[0].observed_value == "absent"
    assert c[0].result is Verdict.PASS
    assert a[0].dependency_fingerprint == "fp"


def test_v04_different_from_repo_without_history(rules: dict) -> None:
    repo = man("repo@x", {"a.nut": b"new"}, "repo")
    rel = man("R1", {"a.nut": b"old"})
    f = compare.rule_v04(repo, rel, {}, rules["V04"], NOW, "fp", "a.nut")[0]
    assert f.result is Verdict.FAIL
    assert "different from repo" in f.message and "older" not in f.message
    assert f.observed_value == sha(b"old") and f.expected_value == sha(b"new")


def test_v04_older_only_when_history_hash_matches(rules: dict) -> None:
    repo = man("repo@cur", {"a.nut": b"new"}, "repo")
    rel = man("R1", {"a.nut": b"old"})
    hist = {"a.nut": [("repo@aaaaaaaaaaaaaaaa", sha(b"old"), "2026-11-01T00:00:00Z")]}
    f = compare.rule_v04(repo, rel, hist, rules["V04"], NOW, "fp", "a.nut")[0]
    assert f.result is Verdict.FAIL and "older" in f.message and "repo@aaaaaaaaaaaaaaaa" in f.message
    hist_other = {"a.nut": [("repo@bbbbbbbbbbbbbbbb", sha(b"unrelated"), "2026-11-01T00:00:00Z")]}
    g = compare.rule_v04(repo, rel, hist_other, rules["V04"], NOW, "fp", "a.nut")[0]
    assert "different from repo" in g.message and "older" not in g.message


def test_repo_history_from_store(tmp_path: Path) -> None:
    store = Store(tmp_path / "c.db")
    try:
        old = man("repo@1111111111111111", {"a.nut": b"old"}, "repo")
        cur = man("repo@2222222222222222", {"a.nut": b"new"}, "repo")
        assert history.record_repo_snapshot(store, old) is True
        assert history.record_repo_snapshot(store, cur) is True
        assert history.record_repo_snapshot(store, cur) is False
        h = history.repo_history(store, PROFILE, exclude_release_id=cur.release_id)
        assert [x[:2] for x in h["a.nut"]] == [("repo@1111111111111111", sha(b"old"))]
    finally:
        store.close()


def test_parse_uninstall_plan_synthetic() -> None:
    plan = compare.parse_uninstall_plan(UNINSTALL_BAT.decode("ascii"))
    assert plan.understood is True
    assert plan.restores == {"tatw.cfg": "GSO/originals/TATW.cfg",
                             "script/main.nut": "GSO/originals/script/main.nut"}
    assert "script/eur40" in plan.removes


def test_parse_uninstall_plan_unknown_line() -> None:
    plan = compare.parse_uninstall_plan('@echo off\r\nxcopy /E "GSO\\originals" "."\r\n')
    assert plan.understood is False and len(plan.unparsed_lines) == 1


@pytest.mark.real
def test_parse_real_054e_uninstall_bat() -> None:
    require(REL_054E)
    with zipfile.ZipFile(REL_054E) as z:
        text = z.read(f"{MOD}/GSO_Uninstall.bat").decode("latin-1")
    plan = compare.parse_uninstall_plan(text)
    assert plan.understood is True, plan.unparsed_lines
    assert plan.restores["script/main.nut"] == "GSO/originals/script/main.nut"
    assert plan.restores["tatw.cfg"] == "GSO/originals/TATW.cfg"
