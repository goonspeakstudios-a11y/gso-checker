"""checker.toml loading, rules catalog loading, glob matching, `sources` inventory.

Contract: ARCHITECTURE.md section 4.1.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

from gso_checker.model import ReleaseSpec, RuleSpec, SourceStatus

logger = logging.getLogger(__name__)

DEFAULT_TEXT_EXTENSIONS: tuple[str, ...] = (
    ".nut", ".txt", ".cfg", ".bat", ".json", ".lua", ".ini", ".xml", ".csv", ".md",
)
DEFAULT_PROCESS_NAMES: tuple[str, ...] = ("M2EX.exe", "medieval2.exe", "kingdoms.exe")


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
    raise NotImplementedError


def release_by_id(cfg: Config, release_id: str) -> ReleaseSpec:
    """Return the configured release. Raises ConfigError if unknown."""
    raise NotImplementedError


def load_rules(path: Path) -> dict[str, RuleSpec]:
    """Load rules/rules_phase1.json -> {rule_id: RuleSpec}.

    Raises ConfigError when a rule misses a key of the rule shape, has an
    authority outside {documented, observed, policy, hypothesis}, or a severity
    outside {blocking, info}.
    """
    raise NotImplementedError


def rule_applies(rule: RuleSpec, profile_id: str) -> bool:
    """True when rule.applies_to_profile contains profile_id or '*'."""
    raise NotImplementedError


def match_glob(normalized_path: str, pattern: str) -> bool:
    """Case-insensitive glob on '/'-separated install-relative paths.

    '**' matches zero or more whole segments, '*' matches within one segment
    (never '/'), '?' one non-'/' char. Whole path must match.
    Examples: 'script/eur40/**' matches 'script/eur40/a.nut' and
    'script/eur40/sub/b.nut' but not 'script/eur40x/a.nut';
    'eopData/sounds/eur40_*' matches 'EOPDATA/sounds/eur40_rain.wav'.
    """
    raise NotImplementedError


def is_gso_owned(cfg: Config, normalized_path: str) -> bool:
    """True when normalized_path matches any cfg.gso_owned glob."""
    raise NotImplementedError


def resolve_sources(cfg: Config) -> list[SourceStatus]:
    """Inventory every configured input, READ-ONLY (spec section 1 `sources`).

    One SourceStatus per: repo_overlay, repo_tools, each release (name
    'release:<id>', sha256 computed and compared with the declared sha256 ->
    note 'sha256 matches declared' / 'sha256 MISMATCH declared <x>'),
    live_mod, game_root, game_exe (sha256), eur_baseline, backups, data_dir,
    rules. Unset optional inputs -> present False, kind 'unset', note
    'not configured'. Never opens anything for writing.
    """
    raise NotImplementedError
