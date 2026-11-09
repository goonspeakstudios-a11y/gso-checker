"""Confirmed install / uninstall: the ONLY code allowed to write under game_root.

Contract: ARCHITECTURE.md 4.12. Writes are restricted to cfg.live_mod (the
mod folder) and to cfg.backups; every target path is checked with
assert_inside before opening it.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from gso_checker.config import Config
from gso_checker.model import InstallRecord, Manifest, Report, RuleSpec, Waiver
from gso_checker.process import ProcessProbe
from gso_checker.store import Store

logger = logging.getLogger(__name__)

from gso_checker.manifest import BACKUP_FILES_DIR, BACKUP_INVENTORY  # noqa: F401  (shared format)


@dataclass(frozen=True)
class InstallPlan:
    release_id: str
    target_root: Path
    copies: tuple[str, ...]           # normalized paths to write (all composed entries)
    replaces: tuple[str, ...]         # subset of copies that exist in live now (to back up)


def assert_inside(root: Path, target: Path) -> Path:
    """Resolve both and return target if it is root or below it, else raise
    ForbiddenWriteError. Used before EVERY write/delete."""
    raise NotImplementedError


def plan_install(cfg: Config, release: Manifest) -> InstallPlan:
    """Plan from the composed manifest: copies = every entry (sorted);
    replaces = entries whose target file exists under cfg.live_mod."""
    raise NotImplementedError


def new_install_id(release_id: str, now_iso: str) -> str:
    """'inst-<YYYYMMDDTHHMMSSZ>-<release_id>' (characters outside [A-Za-z0-9._-]
    replaced by '_')."""
    raise NotImplementedError


def write_backup(cfg: Config, plan: InstallPlan, backup_id: str) -> Manifest:
    """Copy every plan.replaces file from live into
    <cfg.backups>/<backup_id>/files/<normalized_path>, write
    <cfg.backups>/<backup_id>/inventory.json:
      {"backup_id", "created_at_utc", "source_root", "release_id",
       "files": [{"normalized_path", "sha256", "size"}]}
    re-hash every copied file and raise CheckerError on any mismatch.
    Returns the backup as a Manifest (kind='backup', release_id 'backup:<id>')."""
    raise NotImplementedError


def install(cfg: Config, release_id: str, *, confirm: str, probe: ProcessProbe, store: Store,
            rules: Mapping[str, RuleSpec], waivers: Sequence[Waiver] = ()) -> InstallRecord:
    """Confirmed install.

    1. confirm != release_id (exact, case-sensitive) -> ConfirmationError, no writes.
    2. gate.evaluate_gate(...) REFUSE -> GateRefusedError(decision), no writes.
    3. plan_install; write_backup (backup_id = install_id).
    4. For each copy: bytes via manifest.read_release_bytes; write to
       '<target>.gso-tmp' then os.replace; record created dirs.
    5. Post-check: re-hash every installed file against the manifest;
       differing -> post_check FAIL, status 'partial', differing listed.
    6. store.record_install(record); return it.
    """
    raise NotImplementedError


def uninstall(cfg: Config, install_id: str, *, confirm: str, probe: ProcessProbe,
              store: Store) -> InstallRecord:
    """Confirmed uninstall of a recorded install.

    confirm != install_id -> ConfirmationError. Unknown id -> ConfigError.
    probe state not NOT_RUNNING -> raise CheckerError('game running or
    process state unknown'), no writes.
    For each InstalledFile: pre_existed -> restore bytes from the install's
    backup and verify sha256 == pre_sha256; else delete the file. Then remove
    created_dirs that are empty. If an EUR baseline is configured, verify every
    restored path that exists in the baseline has the baseline sha256 (noted in
    the returned record's differing on mismatch). status 'uninstalled' or
    'uninstall-partial'; store.update_install_status.
    """
    raise NotImplementedError


def install_report(record: InstallRecord) -> Report:
    """body_lines: 'install id: <id>', 'backup id: <id>', one
    '<sha256>  <path>' line per installed file, 'post-check: PASS|FAIL'
    (+ differing paths). exit_code 0 when post_check PASS else 1."""
    raise NotImplementedError


def uninstall_report(record: InstallRecord) -> Report:
    """body_lines: 'install id', 'restored: N', 'removed: N', 'EUR originals:
    verified|not configured|MISMATCH <paths>'. exit_code 0 when status
    'uninstalled' else 1."""
    raise NotImplementedError
