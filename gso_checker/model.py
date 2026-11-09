"""Shared data model for gso-checker (phase 1).

This module holds DECLARATIONS ONLY: enums, frozen dataclasses and exception
classes. They are the contract between modules (see ARCHITECTURE.md section 3).
The two helper functions at the bottom are stubs for the builder of model.py.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------
# Enums
# --------------------------------------------------------------------------

class Verdict(str, Enum):
    """Result of one rule evaluation (spec section 2)."""

    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    INFO = "INFO"


class Classification(str, Enum):
    """V01 comparison class of one path between side A and side B."""

    IDENTICAL = "identical"
    DIFFERENT = "different"
    ONLY_A = "only in A"
    ONLY_B = "only in B"
    LINE_ENDINGS = "line-endings-only"


class Packaging(str, Enum):
    """Release packaging type. Only PATCH is composed on its parent."""

    FULL = "full"
    PATCH = "patch"


class PackagingRoot(str, Enum):
    """Where a release ZIP is rooted (ARCHITECTURE.md 4.2)."""

    GAME_ROOT = "game-root"    # entries begin at the game folder (mods/<mod>/...)
    MOD_ROOT = "mod-root"      # entries begin inside the mod folder
    MOD_PARENT = "mod-parent"  # entries begin <mod_folder>/..., extracted into <game_root>/mods


class WorkflowStatus(str, Enum):
    """Human review status (spec section 8). Never changes a Verdict."""

    NONE = ""            # PASS/INFO finding with no decision
    OPEN = "Open"
    FIXED = "Fixed"
    WAIVED = "Waived"
    NOT_A_BUG = "Not a bug"
    ENGINE = "Engine"


class ProcessState(str, Enum):
    """Outcome of a game-process observation."""

    RUNNING = "running"
    NOT_RUNNING = "not_running"
    UNKNOWN = "unknown"


class GateOutcome(str, Enum):
    ALLOW = "ALLOW"
    REFUSE = "REFUSE"


class CacheState(str, Enum):
    CACHED = "cached"
    RECHECKED = "rechecked"


# --------------------------------------------------------------------------
# Config-level records
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ReleaseSpec:
    """One configured release ZIP, in configured order (order 0 = oldest)."""

    release_id: str
    path: Path
    profile_id: str
    packaging: Packaging
    packaging_root: PackagingRoot
    parent: str | None          # composition parent; only used when packaging == PATCH
    order: int
    sha256: str | None = None   # declared ZIP sha256 (optional, verified by `sources`)


@dataclass(frozen=True)
class RuleSpec:
    """One rule from rules/rules_phase1.json (spec section 4 rule shape)."""

    id: str
    version: str
    applies_to_profile: tuple[str, ...]   # ("*",) = every profile
    selector: str
    predicate: str
    expected: str
    severity: str                          # "blocking" | "info"
    authority: str                         # documented | observed | policy | hypothesis
    evidence: tuple[dict[str, str], ...]
    message: str                           # template, str.format(**fields)
    waivable: bool


# --------------------------------------------------------------------------
# Manifests and comparison
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ManifestEntry:
    """One file of a manifest. normalized_path is install-relative (mod folder),
    forward slashes, original spelling. Keys for matching use normalized_path.casefold()."""

    release_id: str
    profile_id: str
    normalized_path: str
    size: int
    sha256: str                  # sha256 of the RAW bytes, never normalized
    eol_sha256: str | None       # sha256 after CRLF->LF, only for text paths, else None
    archive_member: str          # original ZIP member name, or "" for folder trees
    source_release_id: str       # release that contributed the bytes (differs from release_id after compose)


@dataclass(frozen=True)
class Manifest:
    """A complete (composed) file list for one release / tree."""

    release_id: str              # release id, or "repo@<fp16>", "live", "baseline", "backup:<id>"
    profile_id: str
    kind: str                    # "release" | "repo" | "live" | "baseline" | "backup"
    source_path: str             # ZIP path or folder path (absolute, as configured)
    source_sha256: str | None    # ZIP sha256 for ZIP sources, else None
    entries: tuple[ManifestEntry, ...]
    problems: tuple["Finding", ...] = ()   # V02 / V07 findings found while building


@dataclass(frozen=True)
class ComparisonRow:
    normalized_path: str
    classification: Classification
    a_label: str
    b_label: str
    a_sha256: str | None
    b_sha256: str | None
    a_size: int | None
    b_size: int | None


@dataclass(frozen=True)
class AbaHit:
    """V03: release `last` has the same hash as older `first` while `middle` differed."""

    profile_id: str
    normalized_path: str
    first: tuple[str, str]       # (release_id, sha256)
    middle: tuple[str, str]
    last: tuple[str, str]


# --------------------------------------------------------------------------
# Findings and review
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Finding:
    """One rule evaluation record. The first 16 fields are exactly spec section 2."""

    finding_id: str
    rule_id: str
    profile_id: str
    input_id: str
    normalized_path: str
    line: int | None
    result: Verdict
    message: str
    observed_value: str
    expected_value: str
    source_file_or_log: str
    source_line_or_offset: str | None
    source_sha256: str | None
    rule_version: str
    checked_at_utc: str          # ISO 8601, "YYYY-MM-DDTHH:MM:SSZ"
    dependency_fingerprint: str
    # --- extras (not in spec line 64) ---
    blocking: bool = True        # False for INFO and info-severity rules
    waivable: bool = False       # copied from RuleSpec
    cache_state: CacheState = CacheState.RECHECKED


@dataclass(frozen=True)
class ReviewDecision:
    """A human decision imported from a review sheet."""

    finding_id: str
    source_sha256: str | None
    rule_version: str
    dependency_fingerprint: str  # copied from the matched finding at import time
    status: WorkflowStatus
    reason: str
    reviewer: str
    reviewed_at: str
    imported_from: str


@dataclass(frozen=True)
class ReviewedFinding:
    finding: Finding
    status: WorkflowStatus
    reason: str = ""
    reviewer: str = ""
    reviewed_at: str = ""
    reopened: bool = False
    verified_on: str | None = None   # "YYYY-MM-DD" when finding.cache_state is CACHED


@dataclass(frozen=True)
class Waiver:
    """Install-gate waiver for one finding. Empty reason -> gate REFUSE."""

    finding_id: str
    reason: str
    author: str
    date: str


@dataclass(frozen=True)
class SourceStatus:
    """One line of `gso-check sources`."""

    name: str
    path: str
    required_for: str
    present: bool
    kind: str                    # "file" | "dir" | "zip" | "unset"
    mtime_utc: str | None
    sha256: str | None
    note: str = ""


# --------------------------------------------------------------------------
# Process probe
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ProcessInfo:
    image: str
    pid: int
    path: str | None


@dataclass(frozen=True)
class ProcessObservation:
    state: ProcessState
    processes: tuple[ProcessInfo, ...]
    observed_at_utc: str
    method: str                  # e.g. "tasklist+powershell", "tasklist+wmic", "injected"
    detail: str = ""


# --------------------------------------------------------------------------
# Gate and install
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class GateCheck:
    name: str                    # profile | process | manifest | backup | mapping | waivers
    verdict: Verdict             # PASS | FAIL | UNKNOWN
    reason: str
    waivable: bool = False
    waived: bool = False
    finding_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class GateDecision:
    release_id: str
    profile_id: str
    outcome: GateOutcome
    checks: tuple[GateCheck, ...]
    findings: tuple[Finding, ...]
    process: ProcessObservation | None
    decided_at_utc: str


@dataclass(frozen=True)
class InstalledFile:
    normalized_path: str
    sha256: str
    size: int
    pre_existed: bool
    pre_sha256: str | None
    pre_size: int | None


@dataclass(frozen=True)
class InstallRecord:
    install_id: str
    release_id: str
    profile_id: str
    target_root: str             # absolute live mod folder
    backup_id: str
    backup_dir: str
    installed_at_utc: str
    files: tuple[InstalledFile, ...]
    created_dirs: tuple[str, ...]          # install-relative dirs created by install, deepest first
    post_check: Verdict
    differing: tuple[str, ...] = ()
    status: str = "installed"              # installed | partial | uninstalled | uninstall-partial


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Report:
    command: str
    profile_id: str
    release_id: str
    verdict: Verdict | None                # None for commands without a verdict (sources, sheet)
    reason: str
    findings: tuple[ReviewedFinding, ...] = ()
    cached: int = 0
    rechecked: int = 0
    body_lines: tuple[str, ...] = ()       # command-specific lines (rows, gate checks, paths)
    exit_code: int = 0
    text_path: str | None = None
    json_path: str | None = None


# --------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------

class CheckerError(Exception):
    """Base class. CLI maps it to exit code 3."""


class ConfigError(CheckerError):
    pass


class PathEscapeError(CheckerError):
    pass


class ProfileMismatchError(CheckerError):
    pass


class CompositionError(CheckerError):
    pass


class ImmutableRecordError(CheckerError):
    pass


class ConfirmationError(CheckerError):
    pass


class GateRefusedError(CheckerError):
    def __init__(self, decision: GateDecision) -> None:
        super().__init__(f"install-gate REFUSE for {decision.release_id}")
        self.decision = decision


class ForbiddenWriteError(CheckerError):
    """Raised by installer when a write target is outside the allowed root."""


# --------------------------------------------------------------------------
# Helpers (stubs)
# --------------------------------------------------------------------------

def _utcnow() -> datetime:
    """Return the current time as a timezone-aware UTC datetime.

    The ONLY clock in the package. Never datetime.utcnow().
    """
    return datetime.now(timezone.utc)


def utc_iso(dt: datetime) -> str:
    """Format an aware datetime as 'YYYY-MM-DDTHH:MM:SSZ' (UTC, no fraction)."""
    if dt.tzinfo is None:
        raise ValueError("utc_iso needs an aware datetime")
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_finding_id(rule_id: str, profile_id: str, input_id: str,
                    normalized_path: str, line: int | None) -> str:
    """Stable finding id: first 16 hex chars of sha256 over
    f"{rule_id}|{profile_id}|{input_id}|{normalized_path.casefold()}|{'' if line is None else line}"
    encoded UTF-8."""
    key = "%s|%s|%s|%s|%s" % (rule_id, profile_id, input_id, normalized_path.casefold(),
                                  "" if line is None else line)
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
