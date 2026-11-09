"""Local SQLite verification memory. Contract: ARCHITECTURE.md 4.6 and section 5.

The schema below is binding. Builders implement the methods; they may add
indexes but no columns/tables without updating ARCHITECTURE.md.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import contextlib
import sqlite3
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from gso_checker import model
from gso_checker.model import (CacheState, Finding, ImmutableRecordError, InstalledFile,
                               InstallRecord, Manifest, ManifestEntry, ReviewDecision, Verdict,
                               WorkflowStatus)

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


def _now() -> str:
    return model.utc_iso(model._utcnow())


def _content_fp(entries: Iterable[ManifestEntry]) -> str:
    lines = sorted(f"{e.normalized_path.casefold()}\t{e.sha256}\n" for e in entries)
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def finding_to_dict(f: Finding) -> dict[str, Any]:
    """JSON-safe dict of every Finding field."""
    d = dataclasses.asdict(f)
    d["result"] = f.result.value
    d["cache_state"] = f.cache_state.value
    return d


def finding_from_dict(d: dict[str, Any]) -> Finding:
    kw = dict(d)
    kw["result"] = Verdict(kw["result"])
    kw["cache_state"] = CacheState(kw["cache_state"])
    kw["blocking"] = bool(kw["blocking"])
    kw["waivable"] = bool(kw["waivable"])
    return Finding(**kw)


def _install_to_json(r: InstallRecord) -> str:
    d = dataclasses.asdict(r)
    d["post_check"] = r.post_check.value
    return json.dumps(d, sort_keys=True)


def _install_from_json(text: str) -> InstallRecord:
    d = json.loads(text)
    d["files"] = tuple(InstalledFile(**f) for f in d["files"])
    d["created_dirs"] = tuple(d["created_dirs"])
    d["differing"] = tuple(d["differing"])
    d["post_check"] = Verdict(d["post_check"])
    return InstallRecord(**d)


_FINDING_FIELDS: tuple[str, ...] = (
    "finding_id", "rule_id", "profile_id", "input_id", "normalized_path", "line", "result",
    "message", "observed_value", "expected_value", "source_file_or_log",
    "source_line_or_offset", "source_sha256", "rule_version", "checked_at_utc",
    "dependency_fingerprint", "blocking", "waivable", "cache_state",
)


class Store:
    """SQLite wrapper. Opens/creates the db file; never deletes rows except
    `cache` rows being replaced by put_cache."""

    def __init__(self, db_path: Path) -> None:
        """Open (create parent dir + schema if needed)."""
        path = Path(db_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        self.db_path = path
        self._db = sqlite3.connect(str(path))
        self._db.row_factory = sqlite3.Row
        self._db.executescript(SCHEMA_SQL)
        self._db.commit()
        self._batch_depth = 0

    @contextlib.contextmanager
    def batch(self) -> Iterator["Store"]:
        """Group many writes into ONE transaction (commit on clean exit,
        rollback on error). Re-entrant: only the outermost batch commits.
        Writes made outside a batch commit immediately, as before."""
        self._batch_depth += 1
        ok = False
        try:
            yield self
            ok = True
        finally:
            self._batch_depth -= 1
            if self._batch_depth == 0:
                if ok:
                    self._db.commit()
                else:
                    self._db.rollback()

    @contextlib.contextmanager
    def _tx(self) -> Iterator[None]:
        """One write unit: its own transaction, or part of the open batch."""
        if self._batch_depth > 0:
            yield
            return
        with self._db:
            yield

    def close(self) -> None:
        self._db.close()

    def table_names(self) -> list[str]:
        rows = self._db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return sorted(r["name"] for r in rows)

    # --- profiles / manifests -------------------------------------------------
    def ensure_profile(self, profile_id: str, description: str = "") -> None:
        with self._tx():
            self._db.execute(
                "INSERT OR IGNORE INTO profiles(profile_id, description, created_at_utc) "
                "VALUES (?,?,?)", (profile_id, description, _now()))

    def record_manifest(self, manifest: Manifest, *, packaging: str | None = None,
                        packaging_root: str | None = None, parent: str | None = None,
                        ordinal: int | None = None) -> bool:
        fp = _content_fp(manifest.entries)
        row = self._db.execute("SELECT source_sha256, content_fp, profile_id FROM releases "
                               "WHERE release_id=?", (manifest.release_id,)).fetchone()
        if row is not None:
            if (row["source_sha256"] == manifest.source_sha256 and row["content_fp"] == fp
                    and row["profile_id"] == manifest.profile_id):
                return False
            raise ImmutableRecordError(
                f"release {manifest.release_id} already recorded with different content")
        self.ensure_profile(manifest.profile_id)
        with self._tx():
            self._db.execute(
                "INSERT INTO releases(release_id, profile_id, kind, source_path, source_sha256,"
                " content_fp, packaging, packaging_root, parent, ordinal, recorded_at_utc)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (manifest.release_id, manifest.profile_id, manifest.kind, manifest.source_path,
                 manifest.source_sha256, fp, packaging, packaging_root, parent, ordinal, _now()))
            self._db.executemany(
                "INSERT OR REPLACE INTO manifest_entries(release_id, path_key, normalized_path,"
                " size, sha256, eol_sha256, archive_member, source_release_id)"
                " VALUES (?,?,?,?,?,?,?,?)",
                [(manifest.release_id, e.normalized_path.casefold(), e.normalized_path, e.size,
                  e.sha256, e.eol_sha256, e.archive_member, e.source_release_id)
                 for e in manifest.entries])
        return True

    def _build_manifest(self, row: sqlite3.Row) -> Manifest:
        ents = self._db.execute(
            "SELECT * FROM manifest_entries WHERE release_id=? ORDER BY path_key",
            (row["release_id"],)).fetchall()
        entries = tuple(
            ManifestEntry(row["release_id"], row["profile_id"], e["normalized_path"], e["size"],
                          e["sha256"], e["eol_sha256"], e["archive_member"],
                          e["source_release_id"]) for e in ents)
        return Manifest(row["release_id"], row["profile_id"], row["kind"], row["source_path"],
                        row["source_sha256"], entries)

    def get_manifest(self, release_id: str) -> Manifest | None:
        row = self._db.execute("SELECT * FROM releases WHERE release_id=?",
                               (release_id,)).fetchone()
        return None if row is None else self._build_manifest(row)

    def list_manifests(self, profile_id: str, kind: str) -> list[Manifest]:
        rows = self._db.execute(
            "SELECT * FROM releases WHERE profile_id=? AND kind=? "
            "ORDER BY ordinal, recorded_at_utc, release_id", (profile_id, kind)).fetchall()
        return [self._build_manifest(r) for r in rows]

    def known_path_keys(self, profile_id: str, kinds: Sequence[str] = ("release",)) -> set[str]:
        if not kinds:
            return set()
        marks = ",".join("?" for _ in kinds)
        rows = self._db.execute(
            "SELECT DISTINCT m.path_key FROM manifest_entries m JOIN releases r "
            f"ON r.release_id=m.release_id WHERE r.profile_id=? AND r.kind IN ({marks})",
            (profile_id, *kinds)).fetchall()
        return {r["path_key"] for r in rows}

    # --- findings ---------------------------------------------------------------
    def record_findings(self, run_id: str, command: str, findings: Iterable[Finding]) -> None:
        now = _now()
        rows = []
        for f in findings:
            d = finding_to_dict(f)
            rows.append((run_id, *[int(d[k]) if k in ("blocking", "waivable") else d[k]
                                   for k in _FINDING_FIELDS], command, now))
        cols = ",".join(("run_id", *_FINDING_FIELDS, "command", "recorded_at_utc"))
        marks = ",".join("?" for _ in range(len(_FINDING_FIELDS) + 3))
        with self._tx():
            self._db.executemany(f"INSERT OR REPLACE INTO findings({cols}) VALUES ({marks})", rows)

    def latest_finding(self, finding_id: str) -> Finding | None:
        row = self._db.execute(
            "SELECT * FROM findings WHERE finding_id=? ORDER BY rowid DESC LIMIT 1",
            (finding_id,)).fetchone()
        if row is None:
            return None
        return finding_from_dict({k: row[k] for k in _FINDING_FIELDS})

    # --- cache ------------------------------------------------------------------
    def get_cache(self, cache_key: str) -> tuple[str, str, list[Finding], str] | None:
        row = self._db.execute("SELECT * FROM cache WHERE cache_key=?", (cache_key,)).fetchone()
        if row is None:
            return None
        found = [finding_from_dict(d) for d in json.loads(row["findings_json"])]
        return (row["rule_version"], row["dependency_fingerprint"], found,
                row["verified_at_utc"])

    def put_cache(self, cache_key: str, rule_id: str, rule_version: str, profile_id: str,
                  dependency_fingerprint: str, findings: Sequence[Finding],
                  verified_at_utc: str) -> None:
        blob = json.dumps([finding_to_dict(f) for f in findings], sort_keys=True)
        with self._tx():
            self._db.execute(
                "INSERT OR REPLACE INTO cache(cache_key, rule_id, rule_version, profile_id,"
                " dependency_fingerprint, findings_json, verified_at_utc) VALUES (?,?,?,?,?,?,?)",
                (cache_key, rule_id, rule_version, profile_id, dependency_fingerprint, blob,
                 verified_at_utc))

    # --- decisions --------------------------------------------------------------
    def add_decision(self, decision: ReviewDecision) -> None:
        with self._tx():
            self._db.execute(
                "INSERT INTO decisions(finding_id, source_sha256, rule_version,"
                " dependency_fingerprint, status, reason, reviewer, reviewed_at, imported_from,"
                " imported_at_utc) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (decision.finding_id, decision.source_sha256, decision.rule_version,
                 decision.dependency_fingerprint, decision.status.value, decision.reason,
                 decision.reviewer, decision.reviewed_at, decision.imported_from, _now()))

    def latest_decision(self, finding_id: str) -> ReviewDecision | None:
        row = self._db.execute(
            "SELECT * FROM decisions WHERE finding_id=? ORDER BY decision_seq DESC LIMIT 1",
            (finding_id,)).fetchone()
        if row is None:
            return None
        return ReviewDecision(row["finding_id"], row["source_sha256"], row["rule_version"],
                              row["dependency_fingerprint"], WorkflowStatus(row["status"]),
                              row["reason"], row["reviewer"], row["reviewed_at"],
                              row["imported_from"])

    # --- installs ---------------------------------------------------------------
    def record_install(self, record: InstallRecord) -> None:
        if self._db.execute("SELECT 1 FROM installs WHERE install_id=?",
                            (record.install_id,)).fetchone() is not None:
            raise ImmutableRecordError(f"install {record.install_id} already recorded")
        now = _now()
        with self._tx():
            self._db.execute(
                "INSERT INTO installs(install_id, release_id, profile_id, target_root, backup_id,"
                " backup_dir, installed_at_utc, status, post_check, record_json, updated_at_utc)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (record.install_id, record.release_id, record.profile_id, record.target_root,
                 record.backup_id, record.backup_dir, record.installed_at_utc, record.status,
                 record.post_check.value, _install_to_json(record), now))

    def update_install_status(self, install_id: str, status: str, record: InstallRecord) -> None:
        with self._tx():
            cur = self._db.execute(
                "UPDATE installs SET status=?, record_json=?, updated_at_utc=? WHERE install_id=?",
                (status, _install_to_json(dataclasses.replace(record, status=status)), _now(),
                 install_id))
        if cur.rowcount == 0:
            raise ImmutableRecordError(f"unknown install {install_id}")

    def get_install(self, install_id: str) -> InstallRecord | None:
        row = self._db.execute("SELECT record_json, status FROM installs WHERE install_id=?",
                               (install_id,)).fetchone()
        if row is None:
            return None
        return dataclasses.replace(_install_from_json(row["record_json"]), status=row["status"])
