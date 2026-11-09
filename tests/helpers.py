"""Test helpers (test code, not implementation): synthetic worlds, zips,
tree snapshots, injected process probes. Everything is written under tmp_path."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import warnings
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterable, Mapping, Sequence

import pytest

from gso_checker.model import ProcessInfo, ProcessObservation, ProcessState

if TYPE_CHECKING:
    from gso_checker.config import Config
    from gso_checker.model import RuleSpec
    from gso_checker.store import Store

PROFILE = "EUREX-1.5"
MOD = "Divide_and_Conquer_EUR"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "rules" / "rules_phase1.json"

# ---------------------------------------------------------------- real corpus (READ ONLY)
ADDENDUM = Path(r"E:\GSO_checker_addendum_A")
OVERLAY_ZIP = ADDENDUM / "repo" / "overlay_ae4f6169.zip"
RELEASES_JSON = ADDENDUM / "releases" / "releases.json"
REL_054E = Path(r"E:\GSO_054\GSO_0.5.4e.zip")
STALLWATCH = Path(r"E:\M2TW_backup_2026-11-04_gso054\removed_stallwatch_2026-11-08\eur40StallWatch.nut")
LIVE_GAME_ROOT = Path(r"D:\SteamLibrary\steamapps\common\Medieval II Total War")


def require(*paths: Path) -> None:
    """Skip the test cleanly when a real-corpus path is missing."""
    for p in paths:
        if not p.exists():
            pytest.skip(f"real corpus path missing: {p}")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def real_releases(profile: str = PROFILE) -> list[dict[str, str]]:
    """Release rows from the addendum's releases.json for one profile, in file order."""
    rows = json.loads(RELEASES_JSON.read_text(encoding="utf-8"))["releases"]
    return [r for r in rows if r["profile"] == profile]


# ---------------------------------------------------------------- files / zips
def write_tree(root: Path, files: Mapping[str, bytes]) -> None:
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)


def write_zip(path: Path, members: Iterable[tuple[str, bytes]]) -> Path:
    """Write members in the given order. Duplicate names are allowed on purpose."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns on duplicate names
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
            for name, data in members:
                z.writestr(name, data)
    return path


def snapshot_tree(root: Path) -> dict[str, tuple[int, int, str]]:
    """{relative path: (size, mtime_ns, sha256)} for every file, dirs as (-1, mtime_ns, '')."""
    out: dict[str, tuple[int, int, str]] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for d in dirnames:
            p = Path(dirpath) / d
            out[p.relative_to(root).as_posix() + "/"] = (-1, p.stat().st_mtime_ns, "")
        for f in filenames:
            p = Path(dirpath) / f
            st = p.stat()
            out[p.relative_to(root).as_posix()] = (st.st_size, st.st_mtime_ns, sha(p.read_bytes()))
    return out


def content_snapshot(root: Path) -> dict[str, str]:
    """{relative path: sha256} for files and '<dir>/': '' for dirs (no mtimes)."""
    return {k: v[2] for k, v in snapshot_tree(root).items()}


def make_read_only(root: Path) -> None:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            os.chmod(Path(dirpath) / f, stat.S_IREAD)


def make_writable(root: Path) -> None:
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            os.chmod(Path(dirpath) / f, stat.S_IREAD | stat.S_IWRITE)


# ---------------------------------------------------------------- probes
def obs(state: ProcessState, procs: Sequence[ProcessInfo] = ()) -> ProcessObservation:
    return ProcessObservation(state=state, processes=tuple(procs),
                              observed_at_utc="2026-11-08T12:00:00Z", method="injected")


def probe_not_running(names: Sequence[str]) -> ProcessObservation:
    return obs(ProcessState.NOT_RUNNING)


def probe_running(names: Sequence[str]) -> ProcessObservation:
    return obs(ProcessState.RUNNING, [ProcessInfo("M2EX.exe", 4242, r"C:\fake\game\M2EX.exe")])


def probe_unknown(names: Sequence[str]) -> ProcessObservation:
    return obs(ProcessState.UNKNOWN)


# ---------------------------------------------------------------- config writer
def toml_path(p: Path | None) -> str:
    return "" if p is None else p.as_posix()


DEFAULT_OWNED: tuple[str, ...] = (
    "script/eur40/**", "GSO/**", "GSO_Uninstall.bat", "GSO_Clean.bat", "README_GSO.txt",
    "eopData/images/eur40_*", "eopData/sounds/eur40_*",
)


def write_config(path: Path, *, data_dir: Path, game_root: Path, overlay: Path,
                 overlay_prefix: str = "", baseline: Path | None, backups: Path | None,
                 releases: Sequence[Mapping[str, str]], not_installed: Sequence[str] = ("README.txt",),
                 block_extras: bool = False, gso_owned: Sequence[str] = DEFAULT_OWNED,
                 live_mod: Path | None = None) -> Path:
    lines = [
        "[checker]",
        f'data_dir = "{toml_path(data_dir)}"',
        f'profile = "{PROFILE}"',
        f'rules = "{toml_path(RULES_PATH)}"',
        "",
        f'[profiles."{PROFILE}"]',
        'description = "synthetic test profile"',
        "",
        "[game]",
        f'root = "{toml_path(game_root)}"',
        'exe = "M2EX.exe"',
        f'profile = "{PROFILE}"',
        f'mod_folder = "{MOD}"',
        'process_names = ["M2EX.exe"]',
    ]
    if live_mod is not None:
        lines.append(f'live_mod = "{toml_path(live_mod)}"')
    lines += [
        "",
        "[repo]",
        f'overlay = "{toml_path(overlay)}"',
        f'overlay_prefix = "{overlay_prefix}"',
        "not_installed = [" + ", ".join(f'"{n}"' for n in not_installed) + "]",
        'tools = ""',
        "",
        "[eur_baseline]",
        f'path = "{toml_path(baseline)}"',
        f'profile = "{PROFILE}"',
        "",
        "[backups]",
        f'path = "{toml_path(backups)}"',
        "",
        "[ownership]",
        "gso_owned = [" + ", ".join(f'"{g}"' for g in gso_owned) + "]",
        "",
        "[policy]",
        f"block_extras = {'true' if block_extras else 'false'}",
        'text_extensions = [".nut", ".txt", ".cfg", ".bat", ".json"]',
        "",
    ]
    for r in releases:
        lines.append("[[releases]]")
        for k, v in r.items():
            lines.append(f'{k} = "{v}"')
        lines.append("")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


# ---------------------------------------------------------------- synthetic world
EUR_CFG = b"[log]\r\nlevel = info\r\n"
EUR_MAIN = b"// EUR main.nut\r\nrequire(\"eur\")\r\n"
EUR_MENU = b"{EUR_MENU} Menu\r\n"
EUR_OTHER = b"// untouched EUR script\r\n"
GSO_CFG = b"[log]\r\nlevel = info\r\n; [EUR40] gso line\r\n"
GSO_MAIN = b"// EUR main.nut\r\nrequire(\"eur\")\r\n// [EUR40] load eur40\r\n"
CORE_NEW = b"// eur40Core v2\nfunction core() { return 2; }\n"
CORE_OLD = b"// eur40Core v1\nfunction core() { return 1; }\n"

UNINSTALL_BAT = (
    b"@echo off\r\n"
    b"pushd \"%~dp0\"\r\n"
    b"copy /Y \"GSO\\originals\\TATW.cfg\" \"TATW.cfg\" >nul\r\n"
    b"copy /Y \"GSO\\originals\\script\\main.nut\" \"script\\main.nut\" >nul\r\n"
    b"if exist \"script\\eur40\" rmdir /S /Q \"script\\eur40\"\r\n"
    b"if exist \"GSO\" rmdir /S /Q \"GSO\"\r\n"
    b"popd\r\n"
)

CORE_PATH = "script/eur40/eur40Core.nut"


@dataclass
class World:
    root: Path
    config: Path
    game_root: Path
    live: Path
    baseline: Path | None
    backups: Path
    data_dir: Path
    overlay: Path
    good_zip: Path
    stale_zip: Path


def release_members(core: bytes) -> list[tuple[str, bytes]]:
    m = MOD + "/"
    return [
        (m + "TATW.cfg", GSO_CFG),
        (m + "script/main.nut", GSO_MAIN),
        (m + CORE_PATH, core),
        (m + "GSO/originals/TATW.cfg", EUR_CFG),
        (m + "GSO/originals/script/main.nut", EUR_MAIN),
        (m + "GSO_Uninstall.bat", UNINSTALL_BAT),
    ]


def build_world(tmp_path: Path, *, baseline: bool = True, backup: bool = True,
                release_order: Sequence[str] = ("R-stale", "R-good")) -> World:
    """Synthetic EUREX-1.5 install with a pre-GSO live mod, a repo overlay folder,
    two release zips (R-good matches the repo, R-stale has an old eur40Core.nut),
    an optional EUR baseline and an optional pre-existing backup of the originals."""
    root = tmp_path / "world"
    game_root = root / "game"
    live = game_root / "mods" / MOD
    write_tree(game_root, {"M2EX.exe": b"MZ fake exe"})
    eur_files = {
        "TATW.cfg": EUR_CFG,
        "script/main.nut": EUR_MAIN,
        "data/text/menu_english.txt": EUR_MENU,
        "script/eur/other.nut": EUR_OTHER,
    }
    write_tree(live, eur_files)

    base_dir: Path | None = None
    if baseline:
        base_dir = root / "baseline"
        write_tree(base_dir, eur_files)

    backups = root / "backups"
    backups.mkdir(parents=True)
    if backup:
        bdir = backups / "pre_gso_originals"
        write_tree(bdir / "files", {"TATW.cfg": EUR_CFG, "script/main.nut": EUR_MAIN})
        inv = {
            "backup_id": "pre_gso_originals",
            "created_at_utc": "2026-11-01T00:00:00Z",
            "source_root": live.as_posix(),
            "release_id": "",
            "files": [
                {"normalized_path": "TATW.cfg", "sha256": sha(EUR_CFG), "size": len(EUR_CFG)},
                {"normalized_path": "script/main.nut", "sha256": sha(EUR_MAIN), "size": len(EUR_MAIN)},
            ],
        }
        (bdir / "inventory.json").write_text(json.dumps(inv, indent=2), encoding="utf-8")

    overlay = root / "repo" / "overlay"
    write_tree(overlay, {
        "README.txt": b"repo doc, not installed\n",
        "TATW.cfg": GSO_CFG,
        "script/main.nut": GSO_MAIN,
        CORE_PATH: CORE_NEW,
    })

    good_zip = write_zip(root / "zips" / "R-good.zip", release_members(CORE_NEW))
    stale_zip = write_zip(root / "zips" / "R-stale.zip", release_members(CORE_OLD))
    zips = {"R-good": good_zip, "R-stale": stale_zip}
    releases = [
        {"id": rid, "path": zips[rid].as_posix(), "profile": PROFILE,
         "packaging": "full", "packaging_root": "mod-parent"}
        for rid in release_order
    ]
    data_dir = root / "checker_data"
    config = write_config(root / "checker.toml", data_dir=data_dir, game_root=game_root,
                          overlay=overlay, baseline=base_dir, backups=backups, releases=releases)
    return World(root=root, config=config, game_root=game_root, live=live, baseline=base_dir,
                 backups=backups, data_dir=data_dir, overlay=overlay,
                 good_zip=good_zip, stale_zip=stale_zip)


def load_world(world: World) -> "tuple[Config, dict[str, RuleSpec], Store]":
    """Load config, rules and an open Store for a world (calls implementation)."""
    from gso_checker.config import load_config, load_rules
    from gso_checker.store import Store
    cfg = load_config(world.config)
    rules = load_rules(cfg.rules_path)
    store = Store(cfg.db_path)
    return cfg, rules, store
