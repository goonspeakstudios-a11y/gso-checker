"""Unit: SQLite store schema and immutability."""

from __future__ import annotations

from pathlib import Path

import pytest

from gso_checker.model import (ImmutableRecordError, InstalledFile, InstallRecord, Manifest,
                               ManifestEntry, ReviewDecision, Verdict, WorkflowStatus)
from gso_checker.store import TABLES, Store
from tests.helpers import PROFILE, sha


def man(rid: str, files: dict[str, bytes], zip_sha: str | None = "z" * 64) -> Manifest:
    return Manifest(rid, PROFILE, "release", f"E:/{rid}.zip", zip_sha, tuple(
        ManifestEntry(rid, PROFILE, p, len(d), sha(d), None, p, rid) for p, d in sorted(files.items())))


@pytest.fixture()
def store(tmp_path: Path) -> Store:
    s = Store(tmp_path / "db" / "checker.db")
    yield s
    s.close()


def test_schema_has_exactly_the_seven_tables(store: Store) -> None:
    names = [n for n in store.table_names() if not n.startswith("sqlite_")]
    assert sorted(names) == sorted(TABLES)


def test_manifest_roundtrip_and_idempotent(store: Store) -> None:
    m = man("R1", {"a.nut": b"a", "B/c.txt": b"c"})
    assert store.record_manifest(m, packaging="full", packaging_root="mod-parent", ordinal=0) is True
    assert store.record_manifest(m, packaging="full", packaging_root="mod-parent", ordinal=0) is False
    got = store.get_manifest("R1")
    assert got is not None
    assert {e.normalized_path: e.sha256 for e in got.entries} == {e.normalized_path: e.sha256 for e in m.entries}
    assert store.known_path_keys(PROFILE) == {"a.nut", "b/c.txt"}


def test_same_release_id_different_hash_raises(store: Store) -> None:
    store.record_manifest(man("R1", {"a.nut": b"a"}, zip_sha="1" * 64))
    with pytest.raises(ImmutableRecordError):
        store.record_manifest(man("R1", {"a.nut": b"a"}, zip_sha="2" * 64))
    with pytest.raises(ImmutableRecordError):
        store.record_manifest(man("R1", {"a.nut": b"CHANGED"}, zip_sha="1" * 64))
    # the original is untouched
    assert store.get_manifest("R1").entries[0].sha256 == sha(b"a")


def test_list_manifests_by_ordinal(store: Store) -> None:
    store.record_manifest(man("R2", {"a": b"2"}), ordinal=1)
    store.record_manifest(man("R1", {"a": b"1"}), ordinal=0)
    assert [m.release_id for m in store.list_manifests(PROFILE, "release")] == ["R1", "R2"]


def test_latest_decision_wins(store: Store) -> None:
    for status in (WorkflowStatus.FIXED, WorkflowStatus.WAIVED):
        store.add_decision(ReviewDecision("f1", "s" * 64, "1", "fp", status, "why", "BB1",
                                          "2026-11-08T00:00:00Z", "sheet.csv"))
    d = store.latest_decision("f1")
    assert d is not None and d.status is WorkflowStatus.WAIVED and d.reason == "why"
    assert store.latest_decision("other") is None


def test_install_record_roundtrip_and_immutable(store: Store) -> None:
    rec = InstallRecord("inst-1", "R-good", PROFILE, "C:/t", "inst-1", "C:/b/inst-1",
                        "2026-11-08T00:00:00Z",
                        (InstalledFile("a.nut", "a" * 64, 1, True, "b" * 64, 2),), ("script/eur40",),
                        Verdict.PASS)
    store.record_install(rec)
    assert store.get_install("inst-1") == rec
    with pytest.raises(ImmutableRecordError):
        store.record_install(rec)
