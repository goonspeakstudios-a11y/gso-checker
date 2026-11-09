"""Archive/tree manifests, path normalization, patch composition, V02 + V07.

Contract: ARCHITECTURE.md 4.3.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import zipfile
from pathlib import Path
from typing import BinaryIO, Callable, Mapping, Sequence

from gso_checker import hashing
from gso_checker.config import Config
from gso_checker.model import (CacheState, CompositionError, Finding, Manifest, ManifestEntry,
                               Packaging, PackagingRoot, PathEscapeError, ProfileMismatchError,
                               ReleaseSpec, RuleSpec, Verdict, make_finding_id, utc_iso, _utcnow)

logger = logging.getLogger(__name__)

GAME_SCOPE_PREFIX: str = "@game/"
BACKUP_INVENTORY: str = "inventory.json"
BACKUP_FILES_DIR: str = "files"

_DRIVE_RE = re.compile(r"^[A-Za-z]:")


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
    name = member.replace("\\", "/")
    if not name or name.endswith("/"):
        return None
    if name.startswith("/") or _DRIVE_RE.match(name):
        raise PathEscapeError(f"absolute path in archive member: {member!r}")
    if any(seg in ("..", ".") for seg in name.split("/")):
        raise PathEscapeError(f"relative path escape in archive member: {member!r}")
    if packaging_root is PackagingRoot.MOD_PARENT:
        prefix = mod_folder.casefold() + "/"
        if not name.casefold().startswith(prefix):
            raise PathEscapeError(f"member outside {mod_folder}/: {member!r}")
        rest = name[len(prefix):]
    elif packaging_root is PackagingRoot.MOD_ROOT:
        rest = name
    else:
        prefix = f"mods/{mod_folder}/".casefold()
        if name.casefold().startswith(prefix):
            rest = name[len(prefix):]
        else:
            rest = GAME_SCOPE_PREFIX + name
    return rest or None


def _dep_fp(rule_id: str, rule_version: str, profile_id: str, inputs: list[tuple[str, str]]) -> str:
    doc = {"rule_id": rule_id, "rule_version": rule_version, "profile_id": profile_id,
           "inputs": [[k, v] for k, v in sorted(inputs)]}
    return hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _hash_stream(fh: BinaryIO, text: bool) -> tuple[str, str | None, int]:
    """(sha256, eol_sha256 or None, size) of a binary stream, read in chunks."""
    raw = hashlib.sha256()
    eol = hashlib.sha256() if text else None
    size = 0
    carry = b""
    while True:
        chunk = fh.read(hashing.CHUNK_SIZE)
        if not chunk:
            break
        size += len(chunk)
        raw.update(chunk)
        if eol is not None:
            data = carry + chunk
            # hold back a trailing CR so a CRLF split across chunks still normalizes
            if data.endswith(b"\r"):
                carry, data = b"\r", data[:-1]
            else:
                carry = b""
            eol.update(hashing.eol_normalize(data))
    if eol is not None:
        eol.update(carry)
    return raw.hexdigest(), (eol.hexdigest() if eol is not None else None), size


def _finding(rule: RuleSpec | None, rule_id: str, spec_profile: str, input_id: str, path: str,
             result: Verdict, message: str, observed: str, source_file: str, source_sha: str,
             fp: str, checked_at: str) -> Finding:
    version = rule.version if rule is not None else "1"
    return Finding(
        finding_id=make_finding_id(rule_id, spec_profile, input_id, path, None),
        rule_id=rule_id, profile_id=spec_profile, input_id=input_id, normalized_path=path,
        line=None, result=result, message=message, observed_value=observed,
        expected_value=rule.expected if rule is not None else "",
        source_file_or_log=source_file, source_line_or_offset=None, source_sha256=source_sha,
        rule_version=version, checked_at_utc=checked_at, dependency_fingerprint=fp,
        blocking=result is Verdict.FAIL, waivable=bool(rule.waivable) if rule is not None else False,
        cache_state=CacheState.RECHECKED)


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
    zip_sha = hashing.sha256_file(spec.path)
    now = utc_iso(_utcnow())
    v02, v07 = rules.get("V02"), rules.get("V07")
    fp02 = _dep_fp("V02", v02.version if v02 else "1", spec.profile_id, [("zip", zip_sha)])
    fp07 = _dep_fp("V07", v07.version if v07 else "1", spec.profile_id, [("zip", zip_sha)])
    src = str(spec.path)
    rid, prof = spec.release_id, spec.profile_id

    def v02_fail(path: str, msg: str, observed: str) -> Finding:
        return _finding(v02, "V02", prof, rid, path, Verdict.FAIL, msg, observed, src, zip_sha, fp02, now)

    def v07_fail(path: str, problem: str, observed: str) -> Finding:
        msg = (v07.message.format(path=path, problem=problem) if v07 else f"{path}: {problem}")
        return _finding(v07, "V07", prof, rid, path, Verdict.FAIL, msg, observed, src, zip_sha, fp07, now)

    problems: list[Finding] = []
    chosen: dict[str, ManifestEntry] = {}
    spelled: dict[str, list[str]] = {}       # key -> member names (first kept, others collided)
    collided: dict[str, str] = {}            # key -> normalized path of first
    seen_members: set[str] = set()
    dup_reported: set[str] = set()
    escape_reported: set[str] = set()

    with zipfile.ZipFile(spec.path, "r") as zf:
        for info in zf.infolist():
            member = info.filename
            try:
                norm = normalize_member(member, spec.packaging_root, cfg.mod_folder)
            except PathEscapeError as exc:
                if member not in escape_reported:
                    escape_reported.add(member)
                    logger.warning("release %s: %s", rid, exc)
                    problems.append(v07_fail(member.replace("\\", "/"), "path escapes the mod folder", member))
                continue
            if norm is None:
                continue
            if member in seen_members:
                if member not in dup_reported:
                    dup_reported.add(member)
                    msg = (v02.message.format(path=norm, release=rid) if v02
                           else f"{norm}: duplicate archive member in release {rid}")
                    problems.append(v02_fail(norm, msg, member))
                continue
            seen_members.add(member)
            key = norm.casefold()
            if key in chosen:
                first = chosen[key]
                if first.normalized_path != norm:
                    spelled[key].append(member)
                    collided.setdefault(key, first.normalized_path)
                continue
            text = hashing.is_text_path(norm, cfg.text_extensions)
            with zf.open(info, "r") as fh:
                digest, eol, size = _hash_stream(fh, text)
            chosen[key] = ManifestEntry(rid, prof, norm, size, digest, eol, member, rid)
            spelled[key] = [member]

    for key, members in spelled.items():
        if len(members) > 1:
            first_path = chosen[key].normalized_path
            problems.append(v07_fail(first_path, "case-insensitive path collision",
                                     " | ".join(members)))

    if not problems:
        problems = [
            _finding(v02, "V02", prof, rid, "", Verdict.PASS, "no duplicate archive members",
                     "unique members", src, zip_sha, fp02, now),
            _finding(v07, "V07", prof, rid, "", Verdict.PASS, "no path escapes or case collisions",
                     "clean paths", src, zip_sha, fp07, now),
        ]
    entries = tuple(sorted(chosen.values(), key=lambda e: e.normalized_path.casefold()))
    return Manifest(rid, prof, "release", src, zip_sha, entries, tuple(problems))


def build_tree_manifest(root: Path, *, release_id: str, kind: str, profile_id: str,
                        text_extensions: Sequence[str],
                        include: Callable[[str], bool] | None = None) -> Manifest:
    """Walk a folder READ-ONLY and hash every file (or only those where
    include(normalized_path) is True). normalized_path is relative to root with
    '/' separators. archive_member = ''. Missing root -> empty manifest."""
    root = Path(root)
    entries: list[ManifestEntry] = []
    if root.is_dir():
        root_str = os.path.normpath(str(root))
        for dirpath, dirnames, filenames in os.walk(root_str):
            dirnames.sort()
            rel_dir = os.path.relpath(dirpath, root_str).replace("\\", "/")
            rel_dir = "" if rel_dir == "." else rel_dir + "/"
            for fname in sorted(filenames):
                full = os.path.join(dirpath, fname)
                rel = rel_dir + fname
                if include is not None and not include(rel):
                    continue
                text = hashing.is_text_path(rel, text_extensions)
                try:
                    with open(full, "rb") as fh:
                        digest, eol, size = _hash_stream(fh, text)
                except OSError as exc:
                    logger.warning("cannot read %s: %s", full, exc)
                    continue
                entries.append(ManifestEntry(release_id, profile_id, rel, size, digest, eol, "", release_id))
    entries.sort(key=lambda e: e.normalized_path.casefold())
    return Manifest(release_id, profile_id, kind, str(root), None, tuple(entries))


def _content_fp(entries: Sequence[ManifestEntry]) -> str:
    lines = sorted(f"{e.normalized_path.casefold()}\t{e.sha256}\n" for e in entries)
    return hashlib.sha256("".join(lines).encode("utf-8")).hexdigest()


def build_overlay_manifest(cfg: Config) -> Manifest:
    """Manifest of the repo overlay (folder or ZIP), kind='repo'.

    ZIP: members must start with cfg.repo_overlay_prefix (stripped); others ignored.
    Paths in cfg.repo_not_installed are excluded. release_id is
    'repo@' + first 16 hex chars of the content fingerprint
    (sha256 over sorted 'path.casefold()\\tsha256\\n' lines).
    profile_id = cfg.profile_id.
    """
    excluded = {p.replace("\\", "/").casefold() for p in cfg.repo_not_installed}
    src = cfg.repo_overlay
    entries: list[ManifestEntry] = []
    source_sha: str | None = None
    if src.is_dir():
        tree = build_tree_manifest(src, release_id="repo", kind="repo", profile_id=cfg.profile_id,
                                   text_extensions=cfg.text_extensions,
                                   include=lambda p: p.casefold() not in excluded)
        entries = list(tree.entries)
    elif src.is_file():
        source_sha = hashing.sha256_file(src)
        prefix = cfg.repo_overlay_prefix.replace("\\", "/")
        with zipfile.ZipFile(src, "r") as zf:
            for info in zf.infolist():
                name = info.filename.replace("\\", "/")
                if name.endswith("/") or not name.startswith(prefix):
                    continue
                rel = name[len(prefix):]
                if not rel or rel.casefold() in excluded:
                    continue
                if rel.startswith("/") or _DRIVE_RE.match(rel) or any(s in ("..", ".") for s in rel.split("/")):
                    logger.warning("overlay member ignored (unsafe path): %r", info.filename)
                    continue
                text = hashing.is_text_path(rel, cfg.text_extensions)
                with zf.open(info, "r") as fh:
                    digest, eol, size = _hash_stream(fh, text)
                entries.append(ManifestEntry("repo", cfg.profile_id, rel, size, digest, eol,
                                             info.filename, "repo"))
    else:
        logger.warning("repo overlay missing: %s", src)
    rid = "repo@" + _content_fp(entries)[:16]
    out = tuple(sorted((dataclasses.replace(e, release_id=rid, source_release_id=rid) for e in entries),
                       key=lambda e: e.normalized_path.casefold()))
    return Manifest(rid, cfg.profile_id, "repo", str(src), source_sha, out)


def compose(patch: Manifest, parent: Manifest) -> Manifest:
    """Overlay patch entries on parent (key = normalized_path.casefold()).

    Result keeps patch.release_id/profile_id/kind/source_*; parent entries not
    overridden keep their source_release_id; every entry's release_id becomes
    patch.release_id. Different profile_id -> ProfileMismatchError.
    Deletions are not representable in phase 1 (documented limitation).
    """
    if patch.profile_id != parent.profile_id:
        raise ProfileMismatchError(
            f"cannot compose {patch.release_id} ({patch.profile_id}) on {parent.release_id} ({parent.profile_id})")
    merged = {e.normalized_path.casefold(): e for e in parent.entries}
    for e in patch.entries:
        merged[e.normalized_path.casefold()] = e
    entries = tuple(sorted((dataclasses.replace(e, release_id=patch.release_id) for e in merged.values()),
                           key=lambda e: e.normalized_path.casefold()))
    return Manifest(patch.release_id, patch.profile_id, patch.kind, patch.source_path,
                    patch.source_sha256, entries, patch.problems)


def composed_manifest(cfg: Config, release_id: str, rules: Mapping[str, RuleSpec],
                      cache: dict[str, Manifest] | None = None) -> Manifest:
    """Full deployment manifest of a configured release.

    FULL -> build_release_manifest. PATCH -> compose(own, composed_manifest(parent)).
    Unknown parent or a parent cycle -> CompositionError. `cache` (release_id ->
    Manifest) avoids re-reading ZIPs within one run. problems of the parent chain
    are included in the result's problems.
    """
    return _composed(cfg, release_id, rules, cache if cache is not None else {}, ())


def _composed(cfg: Config, release_id: str, rules: Mapping[str, RuleSpec],
              cache: dict[str, Manifest], chain: tuple[str, ...]) -> Manifest:
    if release_id in cache:
        return cache[release_id]
    if release_id in chain:
        raise CompositionError("parent cycle: " + " -> ".join(chain + (release_id,)))
    spec = next((s for s in cfg.releases if s.release_id == release_id), None)
    if spec is None:
        raise CompositionError(f"unknown release or parent: {release_id!r}")
    own = build_release_manifest(spec, cfg, rules)
    if spec.packaging is Packaging.PATCH:
        if not spec.parent:
            raise CompositionError(f"patch release {release_id} has no parent")
        parent = _composed(cfg, spec.parent, rules, cache, chain + (release_id,))
        result = compose(own, parent)
        # keep the whole chain's findings; drop parent PASS rows if we have our own PASS rows
        merged = tuple(own.problems) + tuple(parent.problems)
        result = dataclasses.replace(result, problems=merged)
    else:
        result = own
    cache[release_id] = result
    return result


def read_release_bytes(cfg: Config, release_id: str, normalized_path: str) -> bytes:
    """Bytes of one composed-release file, taken from the ZIP that contributed it
    (follows the patch chain). KeyError if absent."""
    entry = by_key(composed_manifest(cfg, release_id, {})).get(normalized_path.casefold())
    if entry is None:
        raise KeyError(normalized_path)
    spec = next((s for s in cfg.releases if s.release_id == entry.source_release_id), None)
    if spec is None:
        raise KeyError(f"{normalized_path}: source release {entry.source_release_id} not configured")
    with zipfile.ZipFile(spec.path, "r") as zf:
        return zf.read(entry.archive_member)


def by_key(manifest: Manifest) -> dict[str, ManifestEntry]:
    """{normalized_path.casefold(): ManifestEntry} for a manifest."""
    return {e.normalized_path.casefold(): e for e in manifest.entries}


def load_backup_manifests(cfg: Config) -> list[Manifest]:
    """Every <cfg.backups>/*/inventory.json as a Manifest (kind 'backup'),
    hashes taken from the inventory and VERIFIED against the stored files
    (a file whose bytes do not match is left out and logged). Missing or
    unset backups dir -> []."""
    root = cfg.backups
    if root is None or not root.is_dir():
        return []
    out: list[Manifest] = []
    for bdir in sorted(p for p in root.iterdir() if p.is_dir()):
        inv_path = bdir / BACKUP_INVENTORY
        if not inv_path.is_file():
            continue
        try:
            inv = json.loads(inv_path.read_text(encoding="utf-8"))
            files = inv["files"]
            backup_id = str(inv.get("backup_id") or bdir.name)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            logger.warning("unreadable backup inventory %s: %s", inv_path, exc)
            continue
        mid = f"backup:{backup_id}"
        entries: list[ManifestEntry] = []
        for row in files:
            try:
                rel = str(row["normalized_path"]).replace("\\", "/")
                want = str(row["sha256"]).lower()
            except (KeyError, TypeError) as exc:
                logger.warning("bad inventory row in %s: %s", inv_path, exc)
                continue
            if rel.startswith("/") or _DRIVE_RE.match(rel) or any(s in ("..", ".") for s in rel.split("/")):
                logger.warning("backup %s: unsafe path %r left out", backup_id, rel)
                continue
            stored = bdir / BACKUP_FILES_DIR / rel
            text = hashing.is_text_path(rel, cfg.text_extensions)
            try:
                with open(stored, "rb") as fh:
                    digest, eol, size = _hash_stream(fh, text)
            except OSError as exc:
                logger.warning("backup %s: cannot read %s: %s", backup_id, rel, exc)
                continue
            if digest != want:
                logger.warning("backup %s: %s does not match its inventory hash; left out", backup_id, rel)
                continue
            entries.append(ManifestEntry(mid, cfg.profile_id, rel, size, digest, eol, "", mid))
        entries.sort(key=lambda e: e.normalized_path.casefold())
        out.append(Manifest(mid, cfg.profile_id, "backup", str(bdir), None, tuple(entries)))
    return out
