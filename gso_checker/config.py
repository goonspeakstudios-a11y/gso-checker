"""checker.toml loading, rules catalog loading, glob matching, `sources` inventory.

Contract: ARCHITECTURE.md section 4.1.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from gso_checker.hashing import sha256_file
from gso_checker.model import (ConfigError, Packaging, PackagingRoot, ReleaseSpec, RuleSpec,
                               SourceStatus, utc_iso)

logger = logging.getLogger(__name__)

DEFAULT_TEXT_EXTENSIONS: tuple[str, ...] = (
    ".nut", ".txt", ".cfg", ".bat", ".json", ".lua", ".ini", ".xml", ".csv", ".md",
)
DEFAULT_PROCESS_NAMES: tuple[str, ...] = ("M2EX.exe", "medieval2.exe", "kingdoms.exe")

_RULE_KEYS: tuple[str, ...] = (
    "id", "version", "applies_to_profile", "selector", "predicate", "expected",
    "severity", "authority", "waivable", "evidence", "message",
)
_AUTHORITIES = {"documented", "observed", "policy", "hypothesis"}
_SEVERITIES = {"blocking", "info"}


@dataclass(frozen=True)
class Config:
    """Resolved checker.toml. All paths absolute. Optional inputs are None when unset/empty."""

    config_path: Path
    data_dir: Path                       # [checker] data_dir ; holds checker.db and reports/
    profile_id: str                      # [checker] profile
    profiles: dict[str, str]             # [profiles.<id>] description
    game_root: Path                      # [game] root
    game_exe: str                        # [game] exe
    game_profile: str | None             # [game] profile (declared installation profile)
    mod_folder: str                      # [game] mod_folder
    live_mod: Path                       # [game] live_mod, default game_root/"mods"/mod_folder
    process_names: tuple[str, ...]       # [game] process_names
    repo_overlay: Path                   # [repo] overlay (folder or .zip)
    repo_overlay_prefix: str             # [repo] overlay_prefix, e.g. "overlay/" for a git-archive zip
    repo_not_installed: tuple[str, ...]  # [repo] not_installed (install-relative paths)
    repo_tools: Path | None              # [repo] tools
    eur_baseline: Path | None            # [eur_baseline] path ("" -> None)
    eur_baseline_profile: str | None     # [eur_baseline] profile
    backups: Path | None                 # [backups] path
    gso_owned: tuple[str, ...]           # [ownership] gso_owned globs
    block_extras: bool                   # [policy] block_extras
    text_extensions: tuple[str, ...]     # [policy] text_extensions (lowercase, with dot)
    rules_path: Path                     # [checker] rules, default <package parent>/rules/rules_phase1.json
    releases: tuple[ReleaseSpec, ...]    # [[releases]] in file order; order = index

    @property
    def db_path(self) -> Path:
        return self.data_dir / "checker.db"

    @property
    def reports_dir(self) -> Path:
        return self.data_dir / "reports"


def load_config(path: Path) -> Config:
    """Parse checker.toml with tomllib and return a Config.

    Relative paths resolve against path.parent; absolute paths are kept as
    written (no Path.resolve(), no existence check, no directory creation). Raises ConfigError for: missing
    file, TOML syntax error, missing required key ([checker] data_dir, profile;
    [game] root, mod_folder; [repo] overlay), unknown packaging/packaging_root
    value, duplicate release id, packaging="patch" without parent, parent that
    names an unknown release.
    """
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    try:
        doc = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc
    base = path.parent

    def section(name: str) -> dict[str, Any]:
        val = doc.get(name, {})
        if not isinstance(val, dict):
            raise ConfigError(f"[{name}] must be a table")
        return val

    def need(sec: dict[str, Any], sec_name: str, key: str) -> Any:
        if key not in sec or sec[key] in (None, ""):
            raise ConfigError(f"missing required key [{sec_name}] {key}")
        return sec[key]

    def to_path(value: Any) -> Path:
        p = Path(str(value))
        return p if p.is_absolute() else Path(os.path.abspath(base / p))

    def opt_path(value: Any) -> Path | None:
        if value is None or str(value).strip() == "":
            return None
        return to_path(value)

    def str_tuple(value: Any, default: tuple[str, ...]) -> tuple[str, ...]:
        if value is None:
            return default
        if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
            raise ConfigError("expected a list of strings")
        return tuple(value)

    chk, game, repo = section("checker"), section("game"), section("repo")
    base_sec, bak = section("eur_baseline"), section("backups")
    own, pol = section("ownership"), section("policy")

    data_dir = to_path(need(chk, "checker", "data_dir"))
    profile_id = str(need(chk, "checker", "profile"))
    game_root = to_path(need(game, "game", "root"))
    mod_folder = str(need(game, "game", "mod_folder"))
    overlay = to_path(need(repo, "repo", "overlay"))
    rules_raw = chk.get("rules")
    rules_path = (to_path(rules_raw) if rules_raw
                  else Path(__file__).resolve().parent.parent / "rules" / "rules_phase1.json")
    live_mod = opt_path(game.get("live_mod")) or (game_root / "mods" / mod_folder)

    profiles: dict[str, str] = {}
    for pid, pval in section("profiles").items():
        profiles[str(pid)] = str(pval.get("description", "")) if isinstance(pval, dict) else str(pval)

    text_ext = tuple(e.lower() for e in str_tuple(pol.get("text_extensions"), DEFAULT_TEXT_EXTENSIONS))

    releases: list[ReleaseSpec] = []
    seen: set[str] = set()
    rel_rows = doc.get("releases", [])
    if not isinstance(rel_rows, list):
        raise ConfigError("[[releases]] must be an array of tables")
    for idx, row in enumerate(rel_rows):
        if not isinstance(row, dict):
            raise ConfigError(f"[[releases]] entry {idx} is not a table")
        rid = str(need(row, f"releases #{idx}", "id"))
        if rid in seen:
            raise ConfigError(f"duplicate release id {rid}")
        seen.add(rid)
        try:
            packaging = Packaging(str(need(row, f"releases {rid}", "packaging")))
            pk_root = PackagingRoot(str(need(row, f"releases {rid}", "packaging_root")))
        except ValueError as exc:
            raise ConfigError(f"release {rid}: {exc}") from exc
        parent = row.get("parent") or None
        if packaging is Packaging.PATCH and not parent:
            raise ConfigError(f"release {rid}: packaging = patch requires parent")
        declared = row.get("sha256")
        releases.append(ReleaseSpec(
            release_id=rid, path=to_path(need(row, f"releases {rid}", "path")),
            profile_id=str(need(row, f"releases {rid}", "profile")), packaging=packaging,
            packaging_root=pk_root, parent=str(parent) if parent else None, order=idx,
            sha256=str(declared).lower() if declared else None))
    for spec in releases:
        if spec.packaging is Packaging.PATCH and spec.parent not in seen:
            raise ConfigError(f"release {spec.release_id}: unknown parent {spec.parent}")

    return Config(
        config_path=path, data_dir=data_dir, profile_id=profile_id, profiles=profiles,
        game_root=game_root, game_exe=str(game.get("exe", "")),
        game_profile=str(game["profile"]) if game.get("profile") else None,
        mod_folder=mod_folder, live_mod=live_mod,
        process_names=str_tuple(game.get("process_names"), DEFAULT_PROCESS_NAMES),
        repo_overlay=overlay, repo_overlay_prefix=str(repo.get("overlay_prefix", "")),
        repo_not_installed=str_tuple(repo.get("not_installed"), ()),
        repo_tools=opt_path(repo.get("tools")), eur_baseline=opt_path(base_sec.get("path")),
        eur_baseline_profile=str(base_sec["profile"]) if base_sec.get("profile") else None,
        backups=opt_path(bak.get("path")), gso_owned=str_tuple(own.get("gso_owned"), ()),
        block_extras=bool(pol.get("block_extras", False)), text_extensions=text_ext,
        rules_path=rules_path, releases=tuple(releases))


def release_by_id(cfg: Config, release_id: str) -> ReleaseSpec:
    """Return the configured release. Raises ConfigError if unknown."""
    for spec in cfg.releases:
        if spec.release_id == release_id:
            return spec
    raise ConfigError(f"unknown release id {release_id!r}")


def load_rules(path: Path) -> dict[str, RuleSpec]:
    """Load rules/rules_phase1.json -> {rule_id: RuleSpec}.

    Raises ConfigError when a rule misses a key of the rule shape, has an
    authority outside {documented, observed, policy, hypothesis}, or a severity
    outside {blocking, info}.
    """
    try:
        doc = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot load rules {path}: {exc}") from exc
    rows = doc.get("rules") if isinstance(doc, dict) else None
    if not isinstance(rows, list):
        raise ConfigError(f"rules file {path} has no 'rules' list")
    out: dict[str, RuleSpec] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise ConfigError("rule entry is not an object")
        missing = [k for k in _RULE_KEYS if k not in row]
        if missing:
            raise ConfigError(f"rule {row.get('id', '?')} misses keys {missing}")
        if row["authority"] not in _AUTHORITIES:
            raise ConfigError(f"rule {row['id']}: bad authority {row['authority']!r}")
        if row["severity"] not in _SEVERITIES:
            raise ConfigError(f"rule {row['id']}: bad severity {row['severity']!r}")
        if row["id"] in out:
            raise ConfigError(f"duplicate rule id {row['id']}")
        out[row["id"]] = RuleSpec(
            id=str(row["id"]), version=str(row["version"]),
            applies_to_profile=tuple(str(p) for p in row["applies_to_profile"]),
            selector=str(row["selector"]), predicate=str(row["predicate"]),
            expected=str(row["expected"]), severity=row["severity"], authority=row["authority"],
            evidence=tuple({str(k): str(v) for k, v in ev.items()} for ev in row["evidence"]),
            message=str(row["message"]), waivable=bool(row["waivable"]))
    return out


def rule_applies(rule: RuleSpec, profile_id: str) -> bool:
    """True when rule.applies_to_profile contains profile_id or '*'."""
    return "*" in rule.applies_to_profile or profile_id in rule.applies_to_profile


@lru_cache(maxsize=512)
def _segment_regex(segment: str) -> "re.Pattern[str]":
    parts = []
    for ch in segment:
        if ch == "*":
            parts.append("[^/]*")
        elif ch == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(ch))
    return re.compile("".join(parts))


def match_glob(normalized_path: str, pattern: str) -> bool:
    """Case-insensitive glob on '/'-separated install-relative paths.

    '**' matches zero or more whole segments, '*' matches within one segment
    (never '/'), '?' one non-'/' char. Whole path must match.
    Examples: 'script/eur40/**' matches 'script/eur40/a.nut' and
    'script/eur40/sub/b.nut' but not 'script/eur40x/a.nut';
    'eopData/sounds/eur40_*' matches 'EOPDATA/sounds/eur40_rain.wav'.
    """
    path = normalized_path.replace("\\", "/").casefold()
    return _glob_regex(pattern.replace("\\", "/").casefold()).fullmatch(path + "/") is not None


@lru_cache(maxsize=256)
def _glob_regex(pattern: str) -> "re.Pattern[str]":
    """One compiled regex per glob, matched against '<path>/'. Each plain segment
    becomes '<seg>/' and '**' becomes '(?:[^/]*/)*' (zero or more whole segments),
    so '*' and '?' never cross '/' and '**' may match nothing."""
    parts = []
    for seg in pattern.split("/"):
        parts.append("(?:[^/]*/)*" if seg == "**" else _segment_regex(seg).pattern + "/")
    return re.compile("".join(parts))


def is_gso_owned(cfg: Config, normalized_path: str) -> bool:
    """True when normalized_path matches any cfg.gso_owned glob."""
    return any(match_glob(normalized_path, g) for g in cfg.gso_owned)


PHASE2_REQUIRED_FOR: str = "phase 2 gates (optional)"


def is_phase2_source(s: SourceStatus) -> bool:
    """True for inputs used only by phase-2 commands (never block phase 1)."""
    return s.required_for == PHASE2_REQUIRED_FOR


def resolve_sources(cfg: Config) -> list[SourceStatus]:
    """Inventory every configured input, READ-ONLY (spec section 1 `sources`).

    One SourceStatus per: repo_overlay, repo_tools, each release (name
    'release:<id>', sha256 computed and compared with the declared sha256 ->
    note 'sha256 matches declared' / 'sha256 MISMATCH declared <x>'),
    live_mod, game_root, game_exe (sha256), eur_baseline, backups, data_dir,
    rules. Unset optional inputs -> present False, kind 'unset', note
    'not configured' ('not configured (phase 2)' for phase-2-only inputs such
    as repo_tools, see is_phase2_source). Never opens anything for writing.
    """
    out: list[SourceStatus] = []

    def add(name: str, p: Path | None, required_for: str, *, hash_file: bool = False,
            declared: str | None = None) -> None:
        if p is None:
            note = "not configured (phase 2)" if required_for == PHASE2_REQUIRED_FOR else "not configured"
            out.append(SourceStatus(name, "", required_for, False, "unset", None, None, note))
            return
        try:
            exists = p.exists()
        except OSError:
            exists = False
        if not exists:
            out.append(SourceStatus(name, str(p), required_for, False, "file" if p.suffix else "dir",
                                    None, None, "missing"))
            return
        is_dir = p.is_dir()
        kind = "dir" if is_dir else ("zip" if p.suffix.lower() == ".zip" else "file")
        mtime: str | None = None
        digest: str | None = None
        note = ""
        try:
            mtime = utc_iso(datetime.fromtimestamp(p.stat().st_mtime, tz=timezone.utc))
        except (OSError, ValueError, OverflowError) as exc:
            note = f"mtime unavailable: {exc}"
        if hash_file and not is_dir:
            try:
                digest = sha256_file(p)
            except OSError as exc:
                note = f"unreadable: {exc}"
            else:
                if declared:
                    note = ("sha256 matches declared" if digest == declared.lower()
                            else f"sha256 MISMATCH declared {declared}")
        out.append(SourceStatus(name, str(p), required_for, True, kind, mtime, digest, note))

    add("repo_overlay", cfg.repo_overlay, "V01 V04 V05", hash_file=True)
    add("repo_tools", cfg.repo_tools, PHASE2_REQUIRED_FOR)
    for spec in cfg.releases:
        add(f"release:{spec.release_id}", spec.path, "check compare install", hash_file=True,
            declared=spec.sha256)
    add("live_mod", cfg.live_mod, "V05 install")
    add("game_root", cfg.game_root, "install-gate")
    add("game_exe", cfg.game_root / cfg.game_exe if cfg.game_exe else None, "install-gate", hash_file=True)
    add("eur_baseline", cfg.eur_baseline, "V06 install-gate")
    add("backups", cfg.backups, "V06 install")
    add("data_dir", cfg.data_dir, "database and reports")
    add("rules", cfg.rules_path, "all rules", hash_file=True)
    return out
