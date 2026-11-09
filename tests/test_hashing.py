"""Unit: hashing + V01 classification (line endings never normalize the real sha256)."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from gso_checker import hashing
from gso_checker.model import Classification, ManifestEntry

TEXT = (".nut", ".txt", ".cfg")


def entry(path: str, data: bytes) -> ManifestEntry:
    return ManifestEntry(
        release_id="R", profile_id="EUREX-1.5", normalized_path=path, size=len(data),
        sha256=hashing.sha256_bytes(data),
        eol_sha256=hashing.eol_sha256(data, path, TEXT),
        archive_member="", source_release_id="R",
    )


def test_sha256_bytes_and_file_match_hashlib(tmp_path: Path) -> None:
    data = b"abc\r\n" * 1000
    p = tmp_path / "f.bin"
    p.write_bytes(data)
    want = hashlib.sha256(data).hexdigest()
    assert hashing.sha256_bytes(data) == want
    assert hashing.sha256_file(p) == want


def test_is_text_path_case_insensitive() -> None:
    assert hashing.is_text_path("script/A.NUT", TEXT)
    assert not hashing.is_text_path("data/ui/x.tga", TEXT)


def test_eol_normalize_only_crlf() -> None:
    assert hashing.eol_normalize(b"a\r\nb\rc\n") == b"a\nb\rc\n"


def test_line_endings_only_keeps_raw_sha256() -> None:
    crlf, lf = b"x = 1\r\ny = 2\r\n", b"x = 1\ny = 2\n"
    a, b = entry("script/m.nut", crlf), entry("script/m.nut", lf)
    assert a.sha256 == hashlib.sha256(crlf).hexdigest()
    assert b.sha256 == hashlib.sha256(lf).hexdigest()
    assert a.sha256 != b.sha256
    assert hashing.classify(a, b) is Classification.LINE_ENDINGS


def test_binary_never_line_endings_only() -> None:
    a, b = entry("data/ui/x.tga", b"\x00\r\n"), entry("data/ui/x.tga", b"\x00\n")
    assert a.eol_sha256 is None
    assert hashing.classify(a, b) is Classification.DIFFERENT


@pytest.mark.parametrize("a,b,want", [
    (b"same", b"same", Classification.IDENTICAL),
    (b"one", b"two", Classification.DIFFERENT),
    (b"one", None, Classification.ONLY_A),
    (None, b"two", Classification.ONLY_B),
])
def test_classify_classes(a: bytes | None, b: bytes | None, want: Classification) -> None:
    ea = entry("t.txt", a) if a is not None else None
    eb = entry("t.txt", b) if b is not None else None
    assert hashing.classify(ea, eb) is want


def test_classify_both_absent_is_error() -> None:
    with pytest.raises(ValueError):
        hashing.classify(None, None)
