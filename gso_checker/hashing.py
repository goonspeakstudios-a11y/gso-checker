"""SHA-256 helpers and V01 classification. Contract: ARCHITECTURE.md 4.2."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Sequence

from gso_checker.model import Classification, ManifestEntry

logger = logging.getLogger(__name__)

CHUNK_SIZE: int = 1 << 20


def sha256_bytes(data: bytes) -> str:
    """Lowercase hex sha256 of the raw bytes."""
    raise NotImplementedError


def sha256_file(path: Path) -> str:
    """Lowercase hex sha256 of a file, read in CHUNK_SIZE chunks, opened 'rb' only
    (no locks, no writes). Raises OSError if unreadable."""
    raise NotImplementedError


def is_text_path(normalized_path: str, text_extensions: Sequence[str]) -> bool:
    """True when the lowercase suffix of normalized_path is in text_extensions."""
    raise NotImplementedError


def eol_normalize(data: bytes) -> bytes:
    """Replace every b'\\r\\n' with b'\\n'. Used ONLY to compute eol_sha256 for
    classification; the actual sha256 is always over raw bytes."""
    raise NotImplementedError


def eol_sha256(data: bytes, normalized_path: str, text_extensions: Sequence[str]) -> str | None:
    """sha256 of eol_normalize(data) for text paths, None for other paths."""
    raise NotImplementedError


def classify(a: ManifestEntry | None, b: ManifestEntry | None) -> Classification:
    """V01 class: both None -> ValueError; only a -> ONLY_A; only b -> ONLY_B;
    equal sha256 -> IDENTICAL; different sha256 but both eol_sha256 not None and
    equal -> LINE_ENDINGS; otherwise DIFFERENT."""
    raise NotImplementedError
