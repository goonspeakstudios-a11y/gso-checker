"""Confirmed install / uninstall: the ONLY code allowed to write under game_root.

Contract: ARCHITECTURE.md 4.12. Writes are restricted to cfg.live_mod (the
mod folder) and to cfg.backups; every target path is checked with
assert_inside before opening it.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from gso_checker import gate as gate_mod
from gso_checker import model
from gso_checker.config import Config
from gso_checker.manifest import (BACKUP_FILES_DIR, BACKUP_INVENTORY, GAME_SCOPE_PREFIX,  # noqa: F401
                                  composed_manifest)
from gso_checker.model import (CheckerError, ConfigError, ConfirmationError, ForbiddenWriteError,
                               GateOutcome, GateRefusedError, InstalledFile, InstallRecord,
                               Manifest, ManifestEntry, ProcessState, Report, RuleSpec, Verdict,
                               Waiver)
from gso_checker.process import ProcessProbe
from gso_checker.store import Store

logger = logging.getLogger(__name__)

TMP_SUFFIX = ".gso-tmp"
EUR_MISMATCH_PREFIX = "EUR original mismatch: "


@dataclass(frozen=True)
class InstallPlan:
    release_id: str
    target_root: Path
    copies: tuple[str, ...]           # normalized paths to write (all composed entries)
    replaces: tuple[str, ...]         # subset of copies that exist in live now (to back up)


# ------------------------------------------------------------------ helpers
def _parts(p: Path) -> list[str]:
    return [x.casefold() for x in p.resolve().parts]


def assert_inside(root: Path, target: Path) -> Path:
    """Resolve both and return target if it is root or below it, else raise
    ForbiddenWriteError. Used before EVERY write/delete."""
    try:
        r, t = _parts(root), _parts(target)
    except (OSError, RuntimeError) as exc:
        raise ForbiddenWriteError(f"cannot resolve {target}: {exc}") from exc
    if len(t) < len(r) or t[:len(r)] != r:
        raise ForbiddenWriteError(f"write target {target} is outside allowed root {root}")
    return target


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _dest(root: Path, normalized_path: str) -> Path:
    """Destination under `root` for an install-relative path; refuses escapes."""
    if (not normalized_path or normalized_path.startswith(GAME_SCOPE_PREFIX)
            or normalized_path.startswith("/") or "\\" in normalized_path
            or any(seg in ("", ".", "..") for seg in normalized_path.split("/"))
            or ":" in normalized_path.split("/")[0]):
        raise ForbiddenWriteError(f"unsafe install path: {normalized_path!r}")
    return assert_inside(root, root / normalized_path)


def _write_atomic(root: Path, target: Path, data: bytes) -> None:
    """Write via '<target>.gso-tmp' + os.replace; both paths checked."""
    assert_inside(root, target)
    tmp = target.with_name(target.name + TMP_SUFFIX)
    assert_inside(root, tmp)
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, target)
    except OSError:
        try:
            if tmp.exists():
                os.remove(tmp)
        except OSError as exc:
            logger.warning("could not remove temp file %s: %s", tmp, exc)
        raise


# ------------------------------------------------------------------ plan / backup
def plan_install(cfg: Config, release: Manifest) -> InstallPlan:
    """Plan from the composed manifest: copies = every entry (sorted);
    replaces = entries whose target file exists under cfg.live_mod."""
    copies = sorted({e.normalized_path for e in release.entries}, key=lambda p: p.casefold())
    replaces: list[str] = []
    for p in copies:
        target = _dest(cfg.live_mod, p)
        if target.is_dir():
            raise CheckerError(f"install target is a directory, not a file: {target}")
        if target.is_file():
            replaces.append(p)
    return InstallPlan(release.release_id, cfg.live_mod, tuple(copies), tuple(replaces))


def new_install_id(release_id: str, now_iso: str) -> str:
    """'inst-<YYYYMMDDTHHMMSSZ>-<release_id>' (characters outside [A-Za-z0-9._-]
    replaced by '_')."""
    stamp = now_iso.replace("-", "").replace(":", "")
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", release_id)
    return f"inst-{stamp}-{safe}"


def write_backup(cfg: Config, plan: InstallPlan, backup_id: str) -> Manifest:
    """Copy every plan.replaces file from live into
    <cfg.backups>/<backup_id>/files/<normalized_path>, write
    <cfg.backups>/<backup_id>/inventory.json:
      {"backup_id", "created_at_utc", "source_root", "release_id",
       "files": [{"normalized_path", "sha256", "size"}]}
    re-hash every copied file and raise CheckerError on any mismatch.
    Returns the backup as a Manifest (kind='backup', release_id 'backup:<id>')."""
    if cfg.backups is None:
        raise CheckerError("backups folder not configured")
    if not re.fullmatch(r"[A-Za-z0-9._-]+", backup_id):
        raise CheckerError(f"unsafe backup id: {backup_id!r}")
    bdir = assert_inside(cfg.backups, cfg.backups / backup_id)
    if bdir.exists():
        raise CheckerError(f"backup folder already exists: {bdir}")
    files_root = bdir / BACKUP_FILES_DIR
    created_at = model.utc_iso(model._utcnow())
    entries: list[ManifestEntry] = []
    inv_files: list[dict[str, object]] = []
    files_root.mkdir(parents=True)
    for p in plan.replaces:
        src = _dest(plan.target_root, p)
        dst = assert_inside(bdir, files_root / p)
        data = src.read_bytes()
        digest = _sha256_bytes(data)
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(data)
        if _sha256_file(dst) != digest or dst.stat().st_size != len(data):
            raise CheckerError(f"backup verification failed for {p}")
        inv_files.append({"normalized_path": p, "sha256": digest, "size": len(data)})
        entries.append(ManifestEntry(f"backup:{backup_id}", cfg.profile_id, p, len(data), digest,
                                     None, "", f"backup:{backup_id}"))
    inventory = {"backup_id": backup_id, "created_at_utc": created_at,
                 "source_root": plan.target_root.as_posix(), "release_id": plan.release_id,
                 "files": inv_files}
    assert_inside(bdir, bdir / BACKUP_INVENTORY).write_text(
        json.dumps(inventory, indent=2, ensure_ascii=True), encoding="utf-8")
    return Manifest(f"backup:{backup_id}", cfg.profile_id, "backup", str(bdir), None, tuple(entries))


# ------------------------------------------------------------------ install
def _content_key(m: Manifest) -> list[tuple[str, str, int, str, str]]:
    """What the gate approved: every composed path with its sha256, size and the
    ZIP member / release it comes from (patch chains included)."""
    return sorted((e.normalized_path.casefold(), e.sha256, e.size, e.archive_member,
                   e.source_release_id) for e in m.entries)


def _release_sources(cfg: Config, release: Manifest, plan: InstallPlan) -> dict[str, ManifestEntry]:
    keyed = {e.normalized_path.casefold(): e for e in release.entries}
    return {p: keyed[p.casefold()] for p in plan.copies}


def _read_member(zips: dict[str, zipfile.ZipFile], cfg: Config, entry: ManifestEntry) -> bytes:
    spec = next((s for s in cfg.releases if s.release_id == entry.source_release_id), None)
    if spec is None:
        raise CheckerError(f"{entry.normalized_path}: source release {entry.source_release_id} not configured")
    zf = zips.get(spec.release_id)
    if zf is None:
        zf = zipfile.ZipFile(spec.path, "r")
        zips[spec.release_id] = zf
    data = zf.read(entry.archive_member)
    if _sha256_bytes(data) != entry.sha256:
        raise CheckerError(f"{entry.normalized_path}: release bytes changed since the gate "
                           f"(expected sha256 {entry.sha256})")
    return data


def _missing_dirs(root: Path, target: Path) -> list[Path]:
    """Directories between `root` (exclusive) and target's parent that do not exist yet."""
    out: list[Path] = []
    cur = target.parent
    root_r = root.resolve()
    while cur.resolve() != root_r and not cur.exists():
        out.append(cur)
        cur = cur.parent
    return out


def install(cfg: Config, release_id: str, *, confirm: str, probe: ProcessProbe, store: Store,
            rules: Mapping[str, RuleSpec], waivers: Sequence[Waiver] = ()) -> InstallRecord:
    """Confirmed install.
    1. confirm != release_id (exact, case-sensitive) -> ConfirmationError, no writes.
    2. gate.evaluate_gate(...) REFUSE -> GateRefusedError(decision), no writes.
    3. plan_install; write_backup (backup_id = install_id).
    4. For each copy: bytes from the release ZIP that contributed the file (hash-checked
       against the manifest); write to '<target>.gso-tmp' then os.replace; record created dirs.
    5. Post-check: re-hash every installed file against the manifest;
       differing -> post_check FAIL, status 'partial', differing listed.
    6. store.record_install(record); return it.
    """
    if confirm != release_id:
        raise ConfirmationError("confirmation does not match the release id; nothing was changed")
    decision = gate_mod.evaluate_gate(cfg, release_id, probe=probe, store=store, rules=rules,
                                      waivers=waivers)
    if decision.outcome is not GateOutcome.ALLOW:
        raise GateRefusedError(decision)

    release = composed_manifest(cfg, release_id, rules)
    gated = store.get_manifest(release_id)
    if gated is None or _content_key(gated) != _content_key(release):
        raise CheckerError(f"release {release_id} changed after the gate evaluated it; nothing was changed")
    plan = plan_install(cfg, release)
    sources = _release_sources(cfg, release, plan)
    now_iso = model.utc_iso(model._utcnow())
    install_id = new_install_id(release_id, now_iso)

    zips: dict[str, zipfile.ZipFile] = {}
    try:
        # Preflight: every source byte must still match the manifest before anything is written.
        for p in plan.copies:
            _read_member(zips, cfg, sources[p])

        backup = write_backup(cfg, plan, install_id)
        pre = {e.normalized_path: e for e in backup.entries}

        created: set[Path] = set()
        failed: dict[str, str] = {}
        for p in plan.copies:
            target = _dest(plan.target_root, p)
            try:
                data = _read_member(zips, cfg, sources[p])
                new_dirs = _missing_dirs(plan.target_root, target)
                for d in new_dirs:
                    assert_inside(plan.target_root, d)
                target.parent.mkdir(parents=True, exist_ok=True)
                created.update(new_dirs)
                _write_atomic(plan.target_root, target, data)
            except (OSError, CheckerError, zipfile.BadZipFile, KeyError) as exc:
                logger.error("install of %s failed: %s", p, exc)
                failed[p] = str(exc)
    finally:
        for zf in zips.values():
            zf.close()

    differing: list[str] = []
    files: list[InstalledFile] = []
    for p in plan.copies:
        entry = sources[p]
        target = _dest(plan.target_root, p)
        try:
            ok = target.is_file() and _sha256_file(target) == entry.sha256 \
                and target.stat().st_size == entry.size
        except OSError as exc:
            logger.error("post-check read failed for %s: %s", p, exc)
            ok = False
        if not ok or p in failed:
            differing.append(p)
        b = pre.get(p)
        files.append(InstalledFile(p, entry.sha256, entry.size, b is not None,
                                   b.sha256 if b else None, b.size if b else None))

    root_r = plan.target_root.resolve()
    rel_dirs = sorted({d.resolve().relative_to(root_r).as_posix() for d in created},
                      key=lambda x: (-x.count("/"), x))
    record = InstallRecord(
        install_id=install_id, release_id=release_id, profile_id=cfg.profile_id,
        target_root=str(plan.target_root), backup_id=install_id, backup_dir=backup.source_path,
        installed_at_utc=now_iso, files=tuple(files), created_dirs=tuple(rel_dirs),
        post_check=Verdict.PASS if not differing else Verdict.FAIL,
        differing=tuple(differing), status="installed" if not differing else "partial")
    store.record_install(record)
    return record


# ------------------------------------------------------------------ uninstall
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
    the returned record's differing on mismatch, prefixed EUR_MISMATCH_PREFIX).
    status 'uninstalled' or 'uninstall-partial'; store.update_install_status.
    """
    if confirm != install_id:
        raise ConfirmationError("confirmation does not match the install id; nothing was changed")
    record = store.get_install(install_id)
    if record is None:
        raise ConfigError(f"unknown install id: {install_id}")
    if record.status == "uninstalled":
        raise CheckerError(f"install {install_id} is already uninstalled")
    try:
        observed = probe(cfg.process_names)
    except Exception as exc:  # noqa: BLE001 - probe failure = cannot determine
        logger.warning("process probe raised: %s", exc)
        raise CheckerError("game running or process state unknown") from exc
    if observed.state is not ProcessState.NOT_RUNNING:
        raise CheckerError("game running or process state unknown")

    root = cfg.live_mod
    if _parts(Path(record.target_root)) != _parts(root):
        raise CheckerError(f"install target {record.target_root} differs from configured live mod {root}")
    if cfg.backups is None:
        raise CheckerError("backups folder not configured")
    backup_dir = assert_inside(cfg.backups, Path(record.backup_dir))

    failures: list[str] = []
    restored: list[str] = []
    for f in record.files:
        target = _dest(root, f.normalized_path)
        try:
            if f.pre_existed:
                src = assert_inside(backup_dir, backup_dir / BACKUP_FILES_DIR / f.normalized_path)
                data = src.read_bytes()
                if _sha256_bytes(data) != f.pre_sha256:
                    raise CheckerError("backup copy does not match recorded hash")
                target.parent.mkdir(parents=True, exist_ok=True)
                _write_atomic(root, target, data)
                if _sha256_file(target) != f.pre_sha256:
                    raise CheckerError("restored file does not match recorded hash")
                restored.append(f.normalized_path)
            elif target.exists():
                assert_inside(root, target)
                os.remove(target)
        except (OSError, CheckerError) as exc:
            logger.error("uninstall of %s failed: %s", f.normalized_path, exc)
            failures.append(f.normalized_path)

    for d in record.created_dirs:
        dpath = _dest(root, d)
        try:
            if dpath.is_dir() and not any(dpath.iterdir()):
                os.rmdir(dpath)
        except OSError as exc:
            logger.warning("could not remove directory %s: %s", dpath, exc)

    mismatches: list[str] = []
    if cfg.eur_baseline is not None and cfg.eur_baseline.is_dir():
        for p in restored:
            base = cfg.eur_baseline / p
            try:
                if base.is_file() and _sha256_file(base) != _sha256_file(_dest(root, p)):
                    mismatches.append(EUR_MISMATCH_PREFIX + p)
            except OSError as exc:
                logger.error("EUR baseline verification failed for %s: %s", p, exc)
                mismatches.append(EUR_MISMATCH_PREFIX + p)

    differing = tuple(failures + mismatches)
    status = "uninstalled" if not differing else "uninstall-partial"
    updated = dataclasses.replace(record, status=status, differing=differing,
                                  post_check=Verdict.PASS if not differing else Verdict.FAIL)
    store.update_install_status(install_id, status, updated)
    return updated


# ------------------------------------------------------------------ reports
def install_report(record: InstallRecord) -> Report:
    """body_lines: 'install id: <id>', 'backup id: <id>', one
    '<sha256>  <path>' line per installed file, 'post-check: PASS|FAIL'
    (+ differing paths). exit_code 0 when post_check PASS else 1."""
    ok = record.post_check is Verdict.PASS
    lines = [f"install id: {record.install_id}", f"backup id: {record.backup_id}"]
    lines += [f"{f.sha256}  {f.normalized_path}" for f in record.files]
    lines.append(f"post-check: {'PASS' if ok else 'FAIL'}")
    lines += [f"differs: {p}" for p in record.differing]
    reason = (f"Installed {len(record.files)} files; every hash verified." if ok else
              f"Install is partial: {len(record.differing)} file(s) differ after copying.")
    return Report("install", record.profile_id, record.release_id,
                  Verdict.PASS if ok else Verdict.FAIL, reason, (), 0, 0, tuple(lines),
                  0 if ok else 1)


def uninstall_report(record: InstallRecord) -> Report:
    """body_lines: 'install id', 'restored: N', 'removed: N', 'EUR originals:
    verified|not configured|MISMATCH <paths>'. exit_code 0 when status
    'uninstalled' else 1."""
    ok = record.status == "uninstalled"
    restored = sum(1 for f in record.files if f.pre_existed)
    removed = sum(1 for f in record.files if not f.pre_existed)
    mism = [p[len(EUR_MISMATCH_PREFIX):] for p in record.differing if p.startswith(EUR_MISMATCH_PREFIX)]
    others = [p for p in record.differing if not p.startswith(EUR_MISMATCH_PREFIX)]
    if mism:
        eur = "MISMATCH " + ", ".join(mism)
    elif ok:
        eur = "verified"
    else:
        eur = "not verified"
    lines = [f"install id: {record.install_id}", f"restored: {restored}", f"removed: {removed}",
             f"EUR originals: {eur}"]
    lines += [f"failed: {p}" for p in others]
    reason = ("Uninstalled; original files restored and verified." if ok else
              "Uninstall is partial; see the failed or mismatching files.")
    return Report("uninstall", record.profile_id, record.release_id,
                  Verdict.PASS if ok else Verdict.FAIL, reason, (), 0, 0, tuple(lines),
                  0 if ok else 1)
