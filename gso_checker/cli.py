"""Command-line entry: `python -m gso_checker ...`. Contract: ARCHITECTURE.md section 7."""

from __future__ import annotations

import argparse
import logging
from typing import Sequence, TextIO

from gso_checker.process import ProcessProbe

logger = logging.getLogger(__name__)

EXIT_PASS: int = 0
EXIT_FAIL: int = 1
EXIT_UNKNOWN: int = 2
EXIT_USAGE_OR_BLOCKED: int = 3

CONFIG_ENV: str = "GSO_CHECKER_CONFIG"


def build_parser() -> argparse.ArgumentParser:
    """Parser with global '--config PATH' and sub-commands:
      sources
      compare --release ID
      check --release ID [--all]
      install-gate --release ID [--waivers FILE]
      install --release ID [--confirm TEXT] [--waivers FILE]
      uninstall --install ID [--confirm TEXT]
      sheet export --release ID [--out DIR]
      sheet import --file PATH
    argparse errors must surface as exit code 3 (see main)."""
    raise NotImplementedError


def main(argv: Sequence[str] | None = None, *, probe: ProcessProbe | None = None,
         stdin: TextIO | None = None, stdout: TextIO | None = None) -> int:
    """Run one command and return its exit code (never calls sys.exit itself).

    Config path: --config, else env GSO_CHECKER_CONFIG, else ./checker.toml.
    probe defaults to process.SystemProcessProbe(); stdin/stdout default to
    sys.stdin/sys.stdout. install/uninstall without --confirm prompt
    'Type the release id to confirm: ' / 'Type the install id to confirm: '
    on stdout and read one line from stdin.
    Every command writes its report via report.write_report under
    cfg.reports_dir and prints render_text via report.emit.
    Exit codes: 0 PASS/ALLOW/success, 1 FAIL, 2 UNKNOWN, 3 usage error,
    config error, confirmation mismatch, gate REFUSE (blocked).
    CheckerError -> message on stdout + exit 3; no traceback.
    """
    raise NotImplementedError
