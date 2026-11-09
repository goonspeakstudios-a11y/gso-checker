"""SHA-256 helpers and V01 classification. Contract: ARCHITECTURE.md 4.2."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path, PurePosixPath
from typing import Sequence

from gso_checker.model import Classification, ManifestEntry

logger = logging.getLogger(__name__)

CHUNK_SIZE: int = 1 << 20


def sha256_bytes(data: bytes) -> str:
    """Lowercase hex sha256 of the raw bytes."""
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Lowercase hex sha256 of a file, read in CHUNK_SIZE chunks, opened 'rb' only
    (no locks, no writes). Raises OSError if unreadable."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def is_text_path(normalized_path: str, text_extensions: Sequence[str]) -> bool:
    """True when the lowercase suffix of normalized_path is in text_extensions."""
    suffix = PurePosixPath(normalized_path.replace("\\", "/")).suffix.lower()
    return suffix in {e.lower() for e in text_extensions}


def eol_normalize(data: bytes) -> bytes:
    """Replace every b'\\r\\n' with b'\\n'. Used ONLY to compute eol_sha256 for
    classification; the actual sha256 is always over raw bytes."""
    return data.replace(b"\r\n", b"\n")


def eol_sha256(data: bytes, normalized_path: str, text_extensions: Sequence[str]) -> str | None:
    """sha256 of eol_normalize(data) for text paths, None for other paths."""
    if not is_text_path(normalized_path, text_extensions):
        return None
    return sha256_bytes(eol_normalize(data))


def classify(a: ManifestEntry | None, b: ManifestEntry | None) -> Classification:
    """V01 class: both None -> ValueError; only a -> ONLY_A; only b -> ONLY_B;
    equal sha256 -> IDENTICAL; different sha256 but both eol_sha256 not None and
    equal -> LINE_ENDINGS; otherwise DIFFERENT."""
    if a is None and b is None:
        raise ValueError("classify needs at least one entry")
    if b is None:
        return Classification.ONLY_A
    if a is None:
        return Classification.ONLY_B
    if a.sha256 == b.sha256:
        return Classification.IDENTICAL
    if a.eol_sha256 is not None and a.eol_sha256 == b.eol_sha256:
        return Classification.LINE_ENDINGS
    return Classification.DIFFERENT
