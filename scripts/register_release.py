"""Append a [[releases]] block to checker.toml for a new zip, unless the id is already there.

Usage: python scripts/register_release.py --id 0.5.4g --path E:/GSO_054/GSO_0.5.4g.zip
"""
from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)

BLOCK = (
    '\n[[releases]]\nid = "{id}"\npath = "{path}"\nsha256 = "{sha}"\n'
    'profile = "EUREX-1.5"\npackaging = "full"\npackaging_root = "mod-parent"\n'
)


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv: list[str]) -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--id", required=True)
    ap.add_argument("--path", required=True, type=Path)
    ap.add_argument("--config", type=Path, default=Path(__file__).resolve().parent.parent / "checker.toml")
    a = ap.parse_args(argv[1:])
    if not a.path.is_file():
        logger.error("zip not found: %s", a.path)
        return 1
    text = a.config.read_text(encoding="ascii")
    if 'id = "%s"' % a.id in text:
        logger.info("%s already registered in %s", a.id, a.config)
        return 0
    sha = sha256_of(a.path)
    block = BLOCK.format(id=a.id, path=a.path.as_posix(), sha=sha)
    a.config.write_text(text.rstrip("\n") + "\n" + block, encoding="ascii")
    logger.info("registered %s sha256 %s", a.id, sha)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
