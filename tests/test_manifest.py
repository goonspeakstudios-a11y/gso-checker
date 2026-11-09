"""Unit: path normalization, zip manifests (duplicates, case collisions, escapes), compose."""

from __future__ import annotations

from pathlib import Path

import pytest

from gso_checker import config, manifest
from gso_checker.model import (CompositionError, Packaging, PackagingRoot, PathEscapeError,
                               ProfileMismatchError, ReleaseSpec, Verdict)
from tests.helpers import MOD, PROFILE, build_world, sha, write_config, write_tree, write_zip

MP = PackagingRoot.MOD_PARENT


@pytest.mark.parametrize("member,root,want", [
    (f"{MOD}/script/main.nut", PackagingRoot.MOD_PARENT, "script/main.nut"),
    (f"{MOD.lower()}/script/main.nut", PackagingRoot.MOD_PARENT, "script/main.nut"),
    (f"{MOD}\\data\\text\\x.txt", PackagingRoot.MOD_PARENT, "data/text/x.txt"),
    ("script/main.nut", PackagingRoot.MOD_ROOT, "script/main.nut"),
    (f"mods/{MOD}/TATW.cfg", PackagingRoot.GAME_ROOT, "TATW.cfg"),
    ("Americas.bat", PackagingRoot.GAME_ROOT, "@game/Americas.bat"),
    (f"{MOD}/script/", PackagingRoot.MOD_PARENT, None),
])
def test_normalize_member(member: str, root: PackagingRoot, want: str | None) -> None:
    assert manifest.normalize_member(member, root, MOD) == want


@pytest.mark.parametrize("member", [
    f"{MOD}/../evil.nut",
    f"{MOD}/script/../../evil.nut",
    "/abs/evil.nut",
    "C:/Windows/evil.dll",
    "c:\\evil.dll",
    "other_mod/file.txt",        # mod-parent zip member outside the mod folder
])
def test_normalize_member_escape(member: str) -> None:
    with pytest.raises(PathEscapeError):
        manifest.normalize_member(member, MP, MOD)


def _cfg_with_release(tmp_path: Path, members: list[tuple[str, bytes]], rid: str = "R1"):
    w = build_world(tmp_path)
    z = write_zip(tmp_path / f"{rid}.zip", members)
    write_config(w.config, data_dir=w.data_dir, game_root=w.game_root, overlay=w.overlay,
                 baseline=w.baseline, backups=w.backups,
                 releases=[{"id": rid, "path": z.as_posix(), "profile": PROFILE,
                            "packaging": "full", "packaging_root": "mod-parent"}])
    cfg = config.load_config(w.config)
    return cfg, config.load_rules(cfg.rules_path), config.release_by_id(cfg, rid)


def test_release_manifest_hashes_and_pass_rows(tmp_path: Path) -> None:
    cfg, rules, spec = _cfg_with_release(tmp_path, [(f"{MOD}/a.nut", b"a\r\n"), (f"{MOD}/b/c.txt", b"c")])
    m = manifest.build_release_manifest(spec, cfg, rules)
    keyed = manifest.by_key(m)
    assert set(keyed) == {"a.nut", "b/c.txt"}
    assert keyed["a.nut"].sha256 == sha(b"a\r\n")
    assert keyed["a.nut"].eol_sha256 == sha(b"a\n")
    assert keyed["a.nut"].archive_member == f"{MOD}/a.nut"
    assert m.source_sha256 == sha(spec.path.read_bytes())
    results = {(f.rule_id, f.result) for f in m.problems}
    assert results == {("V02", Verdict.PASS), ("V07", Verdict.PASS)}


def test_duplicate_member_is_v02_fail(tmp_path: Path) -> None:
    cfg, rules, spec = _cfg_with_release(tmp_path, [(f"{MOD}/a.nut", b"1"), (f"{MOD}/a.nut", b"2")])
    m = manifest.build_release_manifest(spec, cfg, rules)
    fails = [f for f in m.problems if f.result is Verdict.FAIL]
    assert [f.rule_id for f in fails] == ["V02"]
    assert manifest.by_key(m)["a.nut"].sha256 == sha(b"1")


def test_case_collision_is_v07_fail_naming_both(tmp_path: Path) -> None:
    cfg, rules, spec = _cfg_with_release(
        tmp_path, [(f"{MOD}/script/Main.nut", b"1"), (f"{MOD}/script/main.nut", b"2")])
    m = manifest.build_release_manifest(spec, cfg, rules)
    fails = [f for f in m.problems if f.result is Verdict.FAIL]
    assert len(fails) == 1 and fails[0].rule_id == "V07"
    assert "script/Main.nut" in fails[0].observed_value and "script/main.nut" in fails[0].observed_value
    assert len(m.entries) == 1


def test_path_escape_is_v07_fail_and_excluded(tmp_path: Path) -> None:
    cfg, rules, spec = _cfg_with_release(
        tmp_path, [(f"{MOD}/ok.nut", b"ok"), (f"{MOD}/../../evil.dll", b"x")])
    m = manifest.build_release_manifest(spec, cfg, rules)
    fails = [f for f in m.problems if f.result is Verdict.FAIL]
    assert [f.rule_id for f in fails] == ["V07"]
    assert "evil.dll" in fails[0].observed_value
    assert [e.normalized_path for e in m.entries] == ["ok.nut"]


def test_tree_manifest_include_filter(tmp_path: Path) -> None:
    write_tree(tmp_path / "t", {"script/eur40/a.nut": b"a", "data/x.txt": b"x"})
    m = manifest.build_tree_manifest(tmp_path / "t", release_id="live", kind="live", profile_id=PROFILE,
                                     text_extensions=(".nut", ".txt"),
                                     include=lambda p: p.startswith("script/eur40/"))
    assert [e.normalized_path for e in m.entries] == ["script/eur40/a.nut"]
    assert manifest.build_tree_manifest(tmp_path / "missing", release_id="live", kind="live",
                                        profile_id=PROFILE, text_extensions=()).entries == ()


def test_overlay_manifest_excludes_not_installed(tmp_path: Path) -> None:
    w = build_world(tmp_path)
    cfg = config.load_config(w.config)
    m = manifest.build_overlay_manifest(cfg)
    assert m.kind == "repo" and m.release_id.startswith("repo@") and len(m.release_id) == 5 + 16
    assert "readme.txt" not in manifest.by_key(m)
    assert set(manifest.by_key(m)) == {"tatw.cfg", "script/main.nut", "script/eur40/eur40core.nut"}


def _patch_world(tmp_path: Path, patch_profile: str = PROFILE) -> tuple:
    w = build_world(tmp_path)
    base = write_zip(tmp_path / "base.zip", [(f"{MOD}/a.nut", b"a1"), (f"{MOD}/b.nut", b"b1")])
    patch = write_zip(tmp_path / "patch.zip", [(f"{MOD}/b.nut", b"b2"), (f"{MOD}/c.nut", b"c2")])
    write_config(w.config, data_dir=w.data_dir, game_root=w.game_root, overlay=w.overlay,
                 baseline=w.baseline, backups=w.backups, releases=[
                     {"id": "base", "path": base.as_posix(), "profile": PROFILE,
                      "packaging": "full", "packaging_root": "mod-parent"},
                     {"id": "p1", "path": patch.as_posix(), "profile": patch_profile,
                      "packaging": "patch", "packaging_root": "mod-parent", "parent": "base"},
                 ])
    cfg = config.load_config(w.config)
    return cfg, config.load_rules(cfg.rules_path)


def test_compose_patch_on_parent(tmp_path: Path) -> None:
    cfg, rules = _patch_world(tmp_path)
    m = manifest.composed_manifest(cfg, "p1", rules)
    keyed = manifest.by_key(m)
    assert set(keyed) == {"a.nut", "b.nut", "c.nut"}
    assert keyed["a.nut"].sha256 == sha(b"a1") and keyed["a.nut"].source_release_id == "base"
    assert keyed["b.nut"].sha256 == sha(b"b2") and keyed["b.nut"].source_release_id == "p1"
    assert all(e.release_id == "p1" for e in m.entries)
    assert manifest.read_release_bytes(cfg, "p1", "a.nut") == b"a1"
    assert manifest.read_release_bytes(cfg, "p1", "b.nut") == b"b2"


def test_compose_profile_mismatch_raises(tmp_path: Path) -> None:
    cfg, rules = _patch_world(tmp_path, patch_profile="EUR-2.085-EUREX-1.4.2")
    with pytest.raises(ProfileMismatchError):
        manifest.composed_manifest(cfg, "p1", rules)


def test_compose_direct() -> None:
    from gso_checker.model import Manifest, ManifestEntry

    def m(rid: str, files: dict[str, bytes], profile: str = PROFILE) -> Manifest:
        return Manifest(rid, profile, "release", rid + ".zip", None, tuple(
            ManifestEntry(rid, profile, p, len(d), sha(d), None, p, rid) for p, d in files.items()))

    out = manifest.compose(m("p", {"B.nut": b"2"}), m("base", {"a.nut": b"1", "b.nut": b"1"}))
    keyed = manifest.by_key(out)
    assert keyed["b.nut"].sha256 == sha(b"2") and keyed["b.nut"].normalized_path == "B.nut"
    with pytest.raises(ProfileMismatchError):
        manifest.compose(m("p", {}, "other"), m("base", {}))


def test_unknown_parent_is_composition_error(tmp_path: Path) -> None:
    cfg, rules = _patch_world(tmp_path)
    bad = ReleaseSpec("p2", cfg.releases[1].path, PROFILE, Packaging.PATCH, MP, "nope", 2)
    cfg2 = type(cfg)(**{**cfg.__dict__, "releases": cfg.releases + (bad,)})
    with pytest.raises(CompositionError):
        manifest.composed_manifest(cfg2, "p2", rules)
