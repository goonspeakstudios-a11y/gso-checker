"""Archive/tree manifests, path normalization, patch composition, V02 + V07.

Contract: ARCHITECTURE.md 4.3.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Callable, Mapping, Sequence

from gso_checker.config import Config
from gso_checker.model import Manifest, ManifestEntry, PackagingRoot, ReleaseSpec, RuleSpec

logger = logging.getLogger(__name__)

GAME_SCOPE_PREFIX: str = "@game/"
BACKUP_INVENTORY: str = "inventory.json"
BACKUP_FILES_DIR: str = "files"


def normalize_member(member: str, packaging_root: PackagingRoot, mod_folder: str) -> str | None:
    """Map a ZIP member name to an install-relative path (relative to the mod folder).

    Steps, in order:
      1. Replace '\\' with '/'.
      2. Directory entries (ending with '/') and empty names -> return None.
      3. Absolute names ('/x', '//x', drive 'C:...' with any letter) -> PathEscapeError.
      4. Any segment equal to '..' or '.' -> PathEscapeError (checked on the raw
         name BEFORE prefix stripping, so 'Divide_and_Conquer_EUR/../x' escapes).
      5. Strip the root prefix, comparing case-insensitively:
         MOD_PARENT: must start with '<mod_folder>/' else PathEscapeError;
         MOD_ROOT:   no prefix;
         GAME_ROOT:  'mods/<mod_folder>/' is stripped; any other member becomes
                     GAME_SCOPE_PREFIX + member (game-folder file, not mod file).
      6. Return the remainder with its original spelling; empty remainder -> None.
    """
    raise NotImplementedError


def build_release_manifest(spec: ReleaseSpec, cfg: Config, rules: Mapping[str, RuleSpec]) -> Manifest:
    """Read spec.path (ZIP, read-only) and return its NON-composed manifest.

    kind='release', source_sha256 = sha256 of the ZIP file. Every non-directory
    member is normalized with normalize_member. Problems become findings in
    Manifest.problems (input_id = spec.release_id, source_sha256 = ZIP sha256):
      - PathEscapeError -> V07 FAIL, observed_value = raw member, entry excluded.
      - exact duplicate member names -> V02 FAIL naming the member; first kept.
      - two members whose normalized paths are equal casefolded but spelled
        differently -> V07 FAIL, observed_value = 'a | b' (both members); first kept.
    When no problem is found, problems holds one V02 PASS and one V07 PASS finding
    with normalized_path '' (whole archive).
    Entries are sorted by normalized_path.casefold().
    """
    raise NotImplementedError


def build_tree_manifest(root: Path, *, release_id: str, kind: str, profile_id: str,
                        text_extensions: Sequence[str],
                        include: Callable[[str], bool] | None = None) -> Manifest:
    """Walk a folder READ-ONLY and hash every file (or only those where
    include(normalized_path) is True). normalized_path is relative to root with
    '/' separators. archive_member = ''. Missing root -> empty manifest."""
    raise NotImplementedError


def build_overlay_manifest(cfg: Config) -> Manifest:
    """Manifest of the repo overlay (folder or ZIP), kind='repo'.

    ZIP: members must start with cfg.repo_overlay_prefix (stripped); others ignored.
    Paths in cfg.repo_not_installed are excluded. release_id is
    'repo@' + first 16 hex chars of the content fingerprint
    (sha256 over sorted 'path.casefold()\\tsha256\\n' lines).
    profile_id = cfg.profile_id.
    """
    raise NotImplementedError


def compose(patch: Manifest, parent: Manifest) -> Manifest:
    """Overlay patch entries on parent (key = normalized_path.casefold()).

    Result keeps patch.release_id/profile_id/kind/source_*; parent entries not
    overridden keep their source_release_id; every entry's release_id becomes
    patch.release_id. Different profile_id -> ProfileMismatchError.
    Deletions are not representable in phase 1 (documented limitation).
    """
    raise NotImplementedError


def composed_manifest(cfg: Config, release_id: str, rules: Mapping[str, RuleSpec],
                      cache: dict[str, Manifest] | None = None) -> Manifest:
    """Full deployment manifest of a configured release.

    FULL -> build_release_manifest. PATCH -> compose(own, composed_manifest(parent)).
    Unknown parent or a parent cycle -> CompositionError. `cache` (release_id ->
    Manifest) avoids re-reading ZIPs within one run. problems of the parent chain
    are included in the result's problems.
    """
    raise NotImplementedError


def read_release_bytes(cfg: Config, release_id: str, normalized_path: str) -> bytes:
    """Bytes of one composed-release file, taken from the ZIP that contributed it
    (follows the patch chain). KeyError if absent."""
    raise NotImplementedError


def by_key(manifest: Manifest) -> dict[str, ManifestEntry]:
    """{normalized_path.casefold(): ManifestEntry} for a manifest."""
    raise NotImplementedError


def load_backup_manifests(cfg: Config) -> list[Manifest]:
    """Every <cfg.backups>/*/inventory.json as a Manifest (kind 'backup'),
    hashes taken from the inventory and VERIFIED against the stored files
    (a file whose bytes do not match is left out and logged). Missing or
    unset backups dir -> []."""
    raise NotImplementedError
