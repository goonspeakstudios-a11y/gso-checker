"""Command-line entry: `python -m gso_checker ...`. Contract: ARCHITECTURE.md section 7."""

from __future__ import annotations

import argparse
import dataclasses
import json
import logging
import os
import sqlite3
import sys
from pathlib import Path
from typing import NoReturn, Sequence, TextIO

from gso_checker import compare, config, gate, installer, report, sheet
from gso_checker.model import (CheckerError, ConfigError, GateRefusedError,
                               Report, Verdict, Waiver, WorkflowStatus, _utcnow, utc_iso)
from gso_checker.process import ProcessProbe, SystemProcessProbe
from gso_checker.store import Store

logger = logging.getLogger(__name__)

EXIT_PASS: int = 0
EXIT_FAIL: int = 1
EXIT_UNKNOWN: int = 2
EXIT_USAGE_OR_BLOCKED: int = 3

CONFIG_ENV: str = "GSO_CHECKER_CONFIG"
DEFAULT_CONFIG: str = "checker.toml"

_VERDICT_EXIT: dict[Verdict, int] = {Verdict.PASS: EXIT_PASS, Verdict.FAIL: EXIT_FAIL,
                                     Verdict.UNKNOWN: EXIT_UNKNOWN}


class _UsageError(Exception):
    """argparse rejected the command line."""

    def __init__(self, code: int) -> None:
        super().__init__(code)
        self.code = code


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise _UsageError(EXIT_USAGE_OR_BLOCKED)


def build_parser() -> argparse.ArgumentParser:
    """Parser with global '--config PATH' and the phase-1 sub-commands."""
    p = _Parser(prog="gso_checker", description="Offline checker for GSO releases.")
    p.add_argument("--config", default=None, help="path to checker.toml")
    sub = p.add_subparsers(dest="command", required=True, parser_class=_Parser)

    sub.add_parser("sources", help="inventory every configured input")
    c = sub.add_parser("compare", help="repo vs release vs live")
    c.add_argument("--release", required=True)
    k = sub.add_parser("check", help="version rules V01-V07 for one release")
    k.add_argument("--release", required=True)
    k.add_argument("--all", action="store_true", help="also list PASS findings")
    g = sub.add_parser("install-gate", help="evaluate the install gate (read-only)")
    g.add_argument("--release", required=True)
    g.add_argument("--waivers", default=None, help="JSON list of waivers")
    i = sub.add_parser("install", help="confirmed install")
    i.add_argument("--release", required=True)
    i.add_argument("--confirm", default=None)
    i.add_argument("--waivers", default=None)
    u = sub.add_parser("uninstall", help="confirmed uninstall")
    u.add_argument("--install", required=True)
    u.add_argument("--confirm", default=None)
    s = sub.add_parser("sheet", help="review sheet export/import")
    ssub = s.add_subparsers(dest="sheet_command", required=True, parser_class=_Parser)
    se = ssub.add_parser("export", help="write the review sheet")
    se.add_argument("--release", required=True)
    se.add_argument("--out", default=None)
    si = ssub.add_parser("import", help="import a reviewed sheet")
    si.add_argument("--file", required=True)
    return p


def _refuse_game_folder(cfg: config.Config, what: str, path: Path) -> None:
    """The checker's own files (db, reports, sheets) never go under game_root."""
    if gate.path_inside(cfg.game_root, path):
        raise ConfigError(f"{what} {path} is inside the game folder {cfg.game_root}; refused")


def _stamp() -> str:
    return _utcnow().strftime("%Y%m%dT%H%M%SZ")


def _error_text(profile: str, release: str, message: str) -> str:
    return "\n".join([report.HEADER_FORMAT.format(profile=profile, release=release),
                      f"ERROR: {message}"])


def _read_waivers(path: str | None) -> list[Waiver]:
    if not path:
        return []
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read waivers file {path}: {exc}") from exc
    if not isinstance(data, list):
        raise ConfigError("waivers file must hold a JSON list")
    out: list[Waiver] = []
    for n, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            raise ConfigError(f"waivers entry {n} is not an object")
        out.append(Waiver(str(row.get("finding_id", "")), str(row.get("reason", "")),
                          str(row.get("author", "")), str(row.get("date", ""))))
    return out


def _store_waivers(cfg: config.Config, release_id: str, store: Store,
                   rules: dict) -> list[Waiver]:
    """Valid 'Waived' sheet decisions for the release's current findings."""
    rep = compare.run_check(cfg, release_id, store, rules)
    out: list[Waiver] = []
    for r in rep.findings:
        if r.status is WorkflowStatus.WAIVED and r.finding.waivable:
            out.append(Waiver(r.finding.finding_id, r.reason, r.reviewer, r.reviewed_at[:10]))
    return out


def _prompt(text: str, stdin: TextIO, stdout: TextIO) -> str:
    report.emit_prompt(text, stdout)
    return stdin.readline().rstrip("\r\n")


def _with_exit(rep: Report, code: int) -> Report:
    return dataclasses.replace(rep, exit_code=code)


def _sources(cfg: config.Config) -> Report:
    rows = config.resolve_sources(cfg)
    lines = []
    for s in rows:
        lines.append(f"{'present' if s.present else 'MISSING'} {s.name} | {s.path or '-'} | {s.kind} | "
                     f"mtime {s.mtime_utc or '-'} | sha256 {s.sha256 or '-'} | {s.note or '-'}")
    # Phase-2-only inputs (repo_tools) are listed but never affect the exit code.
    missing = sum(1 for s in rows if not s.present and not config.is_phase2_source(s))
    later = sum(1 for s in rows if not s.present and config.is_phase2_source(s))
    mismatched = sum(1 for s in rows if s.note.startswith("sha256 MISMATCH"))
    if mismatched:
        reason = f"{mismatched} input(s) do not match their declared sha256."
    elif missing:
        reason = f"{missing} of {len(rows)} required inputs are missing or not configured."
    else:
        reason = f"All {len(rows) - later} phase-1 inputs are present."
    if later:
        reason += f" {later} phase-2 input(s) not configured yet."
    code = EXIT_FAIL if mismatched else (EXIT_UNKNOWN if missing else EXIT_PASS)
    return Report("sources", cfg.profile_id, "-", None, reason, body_lines=tuple(lines),
                  exit_code=code)


def _sheet_export(cfg: config.Config, args: argparse.Namespace, store: Store, rules: dict) -> Report:
    rep = compare.run_check(cfg, args.release, store, rules)
    out_dir = Path(args.out) if args.out else cfg.reports_dir
    exported = sheet.export_sheet(list(rep.findings), out_dir, args.release)
    lines = [f"csv: {exported.csv_path.as_posix()}",
             f"xlsx: {exported.xlsx_path.as_posix()}" if exported.xlsx_path else f"xlsx: {exported.note}",
             f"rows: {exported.rows}"]
    return Report("sheet export", cfg.profile_id, args.release, None,
                  f"Review sheet written for release {args.release}.", body_lines=tuple(lines))


def _sheet_import(cfg: config.Config, args: argparse.Namespace, store: Store) -> Report:
    result = sheet.import_sheet(Path(args.file), store, imported_at_utc=utc_iso(_utcnow()))
    lines = [f"accepted {d.finding_id} {d.status.value}" for d in result.accepted]
    lines += [f"rejected row {n} {fid}: {why}" for n, fid, why in result.rejected]
    reason = f"{len(result.accepted)} decisions accepted, {len(result.rejected)} rows rejected."
    return Report("sheet import", cfg.profile_id, "-", None, reason, body_lines=tuple(lines),
                  exit_code=EXIT_FAIL if result.rejected else EXIT_PASS)


def _run(cfg: config.Config, args: argparse.Namespace, store: Store, probe: ProcessProbe,
         stdin: TextIO, stdout: TextIO) -> Report:
    rules = config.load_rules(cfg.rules_path)
    cmd = args.command
    if cmd == "sources":
        return _sources(cfg)
    if cmd in ("compare", "check"):
        rep = (compare.run_compare if cmd == "compare" else compare.run_check)(cfg, args.release, store, rules)
        return _with_exit(rep, _VERDICT_EXIT.get(rep.verdict, EXIT_UNKNOWN) if rep.verdict else EXIT_UNKNOWN)
    if cmd == "install-gate":
        waivers = _read_waivers(args.waivers) + _store_waivers(cfg, args.release, store, rules)
        decision = gate.evaluate_gate(cfg, args.release, probe=probe, store=store, rules=rules,
                                      waivers=waivers)
        return gate.gate_report(decision)
    if cmd == "install":
        confirm = args.confirm if args.confirm is not None else _prompt(
            "Type the release id to confirm: ", stdin, stdout)
        waivers = _read_waivers(args.waivers) + _store_waivers(cfg, args.release, store, rules)
        try:
            record = installer.install(cfg, args.release, confirm=confirm, probe=probe, store=store,
                                       rules=rules, waivers=waivers)
        except GateRefusedError as exc:
            return _with_exit(gate.gate_report(exc.decision), EXIT_USAGE_OR_BLOCKED)
        return installer.install_report(record)
    if cmd == "uninstall":
        confirm = args.confirm if args.confirm is not None else _prompt(
            "Type the install id to confirm: ", stdin, stdout)
        record = installer.uninstall(cfg, args.install, confirm=confirm, probe=probe, store=store)
        return installer.uninstall_report(record)
    if args.sheet_command == "export":
        return _sheet_export(cfg, args, store, rules)
    return _sheet_import(cfg, args, store)


def main(argv: Sequence[str] | None = None, *, probe: ProcessProbe | None = None,
         stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run one command and return its exit code (never calls sys.exit itself)."""
    out = stdout if stdout is not None else sys.stdout
    inp = stdin if stdin is not None else sys.stdin
    try:
        args = build_parser().parse_args(list(argv) if argv is not None else None)
    except _UsageError as exc:
        return exc.code
    except SystemExit as exc:  # --help
        return exc.code if isinstance(exc.code, int) and exc.code == 0 else EXIT_USAGE_OR_BLOCKED

    cfg_path = Path(args.config or os.environ.get(CONFIG_ENV) or DEFAULT_CONFIG)
    profile, release = "-", getattr(args, "release", None) or "-"
    store: Store | None = None
    try:
        cfg = config.load_config(cfg_path)
        profile = cfg.profile_id
        _refuse_game_folder(cfg, "data_dir", cfg.data_dir)
        _refuse_game_folder(cfg, "reports folder", cfg.reports_dir)
        if getattr(args, "out", None):
            _refuse_game_folder(cfg, "--out", Path(args.out))
        store = Store(cfg.db_path)
        rep = _run(cfg, args, store, probe if probe is not None else SystemProcessProbe(), inp, out)
        show_pass = bool(getattr(args, "all", False))
        rep = report.write_report(rep, cfg.reports_dir, _stamp(), show_pass=show_pass)
        report.emit(report.render_text(rep, show_pass=show_pass), out)
        return rep.exit_code
    except (CheckerError, OSError, sqlite3.Error) as exc:
        if not isinstance(exc, CheckerError):
            logger.error("command failed: %s", exc)
        report.emit(_error_text(profile, release, str(exc)), out)
        return EXIT_USAGE_OR_BLOCKED
    finally:
        if store is not None:
            store.close()
