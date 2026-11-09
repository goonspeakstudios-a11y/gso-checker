"""Local SQLite verification memory. Contract: ARCHITECTURE.md 4.6 and section 5.

The schema below is binding. Builders implement the methods; they may add
indexes but no columns/tables without updating ARCHITECTURE.md.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, Sequence

from gso_checker.model import Finding, InstallRecord, Manifest, ReviewDecision

logger = logging.getLogger(__name__)

SCHEMA_VERSION: int = 1

SCHEMA_SQL: str = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS profiles (
    profile_id      TEXT PRIMARY KEY,
    description     TEXT NOT NULL DEFAULT '',
    created_at_utc  TEXT NOT NULL
);

-- One row per immutable manifest: releases, repo snapshots, live/baseline/backup trees.
CREATE TABLE IF NOT EXISTS releases (
    release_id      TEXT PRIMARY KEY,
    profile_id      TEXT NOT NULL REFERENCES profiles(profile_id),
    kind            TEXT NOT NULL CHECK (kind IN ('release','repo','live','baseline','backup')),
    source_path     TEXT NOT NULL,
    source_sha256   TEXT,                -- ZIP sha256; NULL for folder trees
    content_fp      TEXT NOT NULL,       -- sha256 over sorted 'key\\tsha256\\n' lines
    packaging       TEXT,                -- full | patch | NULL for non-release kinds
    packaging_root  TEXT,
    parent          TEXT,
    ordinal         INTEGER,             -- configured order for kind='release', else NULL
    recorded_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS manifest_entries (
    release_id        TEXT NOT NULL REFERENCES releases(release_id),
    path_key          TEXT NOT NULL,     -- normalized_path.casefold()
    normalized_path   TEXT NOT NULL,
    size              INTEGER NOT NULL,
    sha256            TEXT NOT NULL,
    eol_sha256        TEXT,
    archive_member    TEXT NOT NULL,
    source_release_id TEXT NOT NULL,
    PRIMARY KEY (release_id, path_key)
);

-- Append-only: one row per finding per run.
CREATE TABLE IF NOT EXISTS findings (
    run_id                 TEXT NOT NULL,
    finding_id             TEXT NOT NULL,
    rule_id                TEXT NOT NULL,
    profile_id             TEXT NOT NULL,
    input_id               TEXT NOT NULL,
    normalized_path        TEXT NOT NULL,
    line                   INTEGER,
    result                 TEXT NOT NULL CHECK (result IN ('PASS','FAIL','UNKNOWN','INFO')),
    message                TEXT NOT NULL,
    observed_value         TEXT NOT NULL,
    expected_value         TEXT NOT NULL,
    source_file_or_log     TEXT NOT NULL,
    source_line_or_offset  TEXT,
    source_sha256          TEXT,
    rule_version           TEXT NOT NULL,
    checked_at_utc         TEXT NOT NULL,
    dependency_fingerprint TEXT NOT NULL,
    blocking               INTEGER NOT NULL,
    waivable               INTEGER NOT NULL,
    cache_state            TEXT NOT NULL,
    command                TEXT NOT NULL,
    recorded_at_utc        TEXT NOT NULL,
    PRIMARY KEY (run_id, finding_id)
);

-- Append-only human decisions; the latest row per finding_id wins.
CREATE TABLE IF NOT EXISTS decisions (
    decision_seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id             TEXT NOT NULL,
    source_sha256          TEXT,
    rule_version           TEXT NOT NULL,
    dependency_fingerprint TEXT NOT NULL,
    status                 TEXT NOT NULL CHECK (status IN ('Open','Fixed','Waived','Not a bug','Engine')),
    reason                 TEXT NOT NULL,
    reviewer               TEXT NOT NULL,
    reviewed_at            TEXT NOT NULL,
    imported_from          TEXT NOT NULL,
    imported_at_utc        TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS installs (
    install_id       TEXT PRIMARY KEY,
    release_id       TEXT NOT NULL,
    profile_id       TEXT NOT NULL,
    target_root      TEXT NOT NULL,
    backup_id        TEXT NOT NULL,
    backup_dir       TEXT NOT NULL,
    installed_at_utc TEXT NOT NULL,
    status           TEXT NOT NULL,
    post_check       TEXT NOT NULL,
    record_json      TEXT NOT NULL,      -- full InstallRecord as JSON
    updated_at_utc   TEXT NOT NULL
);

-- Latest evaluation per evaluation unit (see ARCHITECTURE.md section 6).
CREATE TABLE IF NOT EXISTS cache (
    cache_key              TEXT PRIMARY KEY,
    rule_id                TEXT NOT NULL,
    rule_version           TEXT NOT NULL,
    profile_id             TEXT NOT NULL,
    dependency_fingerprint TEXT NOT NULL,
    findings_json          TEXT NOT NULL, -- JSON list of Finding dicts
    verified_at_utc        TEXT NOT NULL
);
"""

TABLES: tuple[str, ...] = (
    "profiles", "releases", "manifest_entries", "findings", "decisions", "installs", "cache",
)


class Store:
    """SQLite wrapper. Opens/creates the db file; never deletes rows except
    `cache` rows being replaced by put_cache."""

    def __init__(self, db_path: Path) -> None:
        """Open (create parent dir + schema if needed)."""
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError

    def table_names(self) -> list[str]:
        """Names of user tables in the db (sorted)."""
        raise NotImplementedError

    # --- profiles / manifests -------------------------------------------------
    def ensure_profile(self, profile_id: str, description: str = "") -> None:
        """Insert if absent; never updates an existing row."""
        raise NotImplementedError

    def record_manifest(self, manifest: Manifest, *, packaging: str | None = None,
                        packaging_root: str | None = None, parent: str | None = None,
                        ordinal: int | None = None) -> bool:
        """Store an immutable manifest. Returns True if inserted, False if an
        identical record (same source_sha256 AND same content_fp AND same
        profile_id) already exists. Any difference for an existing release_id
        -> ImmutableRecordError. Calls ensure_profile."""
        raise NotImplementedError

    def get_manifest(self, release_id: str) -> Manifest | None:
        """Rebuild a stored manifest (problems=())."""
        raise NotImplementedError

    def list_manifests(self, profile_id: str, kind: str) -> list[Manifest]:
        """Stored manifests of one profile and kind, ordered by ordinal then
        recorded_at_utc."""
        raise NotImplementedError

    def known_path_keys(self, profile_id: str, kinds: Sequence[str] = ("release",)) -> set[str]:
        """Union of path_key over stored manifests of the given kinds/profile."""
        raise NotImplementedError

    # --- findings ---------------------------------------------------------------
    def record_findings(self, run_id: str, command: str, findings: Iterable[Finding]) -> None:
        raise NotImplementedError

    def latest_finding(self, finding_id: str) -> Finding | None:
        """Most recently recorded row for finding_id."""
        raise NotImplementedError

    # --- cache ------------------------------------------------------------------
    def get_cache(self, cache_key: str) -> tuple[str, str, list[Finding], str] | None:
        """(rule_version, dependency_fingerprint, findings, verified_at_utc) or None."""
        raise NotImplementedError

    def put_cache(self, cache_key: str, rule_id: str, rule_version: str, profile_id: str,
                  dependency_fingerprint: str, findings: Sequence[Finding],
                  verified_at_utc: str) -> None:
        """Insert or replace one cache row."""
        raise NotImplementedError

    # --- decisions --------------------------------------------------------------
    def add_decision(self, decision: ReviewDecision) -> None:
        raise NotImplementedError

    def latest_decision(self, finding_id: str) -> ReviewDecision | None:
        raise NotImplementedError

    # --- installs ---------------------------------------------------------------
    def record_install(self, record: InstallRecord) -> None:
        """Insert; existing install_id -> ImmutableRecordError."""
        raise NotImplementedError

    def update_install_status(self, install_id: str, status: str, record: InstallRecord) -> None:
        """Only status/record_json/updated_at_utc may change."""
        raise NotImplementedError

    def get_install(self, install_id: str) -> InstallRecord | None:
        raise NotImplementedError
