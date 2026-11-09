"""Unit + A02 synthetic: A-B-A detection."""

from __future__ import annotations

from gso_checker import history
from gso_checker.model import Manifest, ManifestEntry, Verdict
from gso_checker.config import load_rules
from tests.helpers import PROFILE, RULES_PATH, sha


def man(rid: str, files: dict[str, bytes], profile: str = PROFILE) -> Manifest:
    return Manifest(rid, profile, "release", f"{rid}.zip", None, tuple(
        ManifestEntry(rid, profile, p, len(d), sha(d), None, p, rid) for p, d in sorted(files.items())))


def test_synthetic_aba_exactly_one_path_three_ids() -> None:
    ms = [man("R1", {"x.nut": b"A", "y.nut": b"1"}),
          man("R2", {"x.nut": b"B", "y.nut": b"2"}),
          man("R3", {"x.nut": b"A", "y.nut": b"3"})]
    hits = history.find_aba(ms)
    assert len(hits) == 1
    h = hits[0]
    assert h.normalized_path == "x.nut"
    assert (h.first[0], h.middle[0], h.last[0]) == ("R1", "R2", "R3")
    assert h.first[1] == h.last[1] == sha(b"A") and h.middle[1] == sha(b"B")

    rule = load_rules(RULES_PATH)["V03"]
    fs = history.rule_v03(ms, rule, "2026-11-08T00:00:00Z")
    assert len(fs) == 1 and fs[0].result is Verdict.FAIL and fs[0].rule_id == "V03"
    for rid in ("R1", "R2", "R3"):
        assert rid in fs[0].message and rid in fs[0].observed_value
    assert fs[0].input_id == "R3"


def test_no_hit_for_monotone_changes() -> None:
    assert history.find_aba([man("R1", {"x": b"A"}), man("R2", {"x": b"A"}), man("R3", {"x": b"B"})]) == []
    assert history.find_aba([man("R1", {"x": b"A"}), man("R2", {"x": b"B"}), man("R3", {"x": b"B"})]) == []


def test_absent_middle_is_not_a_change() -> None:
    assert history.find_aba([man("R1", {"x": b"A"}), man("R2", {}), man("R3", {"x": b"A"})]) == []


def test_abca_flags_with_latest_matching_first() -> None:
    hits = history.find_aba([man("R1", {"x": b"A"}), man("R2", {"x": b"B"}),
                             man("R3", {"x": b"C"}), man("R4", {"x": b"A"})])
    assert [(h.first[0], h.middle[0], h.last[0]) for h in hits] == [("R1", "R3", "R4")]


def test_path_key_is_case_insensitive() -> None:
    hits = history.find_aba([man("R1", {"X.nut": b"A"}), man("R2", {"x.nut": b"B"}), man("R3", {"x.NUT": b"A"})])
    assert len(hits) == 1 and hits[0].normalized_path == "x.NUT"


def test_never_compares_across_profiles() -> None:
    ms = [man("R1", {"x": b"A"}), man("O1", {"x": b"B"}, profile="EUR-2.085-EUREX-1.4.2"),
          man("R3", {"x": b"A"})]
    assert history.find_aba(ms) == []
