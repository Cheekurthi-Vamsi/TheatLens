from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from threatlens.security.hashing import (
    FileHasher,
    FileTooLargeError,
    NotARegularFileError,
    normalize_path,
)


def test_sha256_matches_hashlib(tmp_path: Path) -> None:
    target = tmp_path / "sample.bin"
    data = os.urandom(3 * 1024 * 1024 + 17)  # spans multiple chunks
    target.write_bytes(data)
    assert FileHasher().sha256(target) == hashlib.sha256(data).hexdigest()


def test_result_is_cached_by_fingerprint(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    hasher = FileHasher()
    hasher.sha256(target)
    hasher.sha256(target)
    assert hasher.cache.hits == 1


def test_modified_file_is_rehashed(tmp_path: Path) -> None:
    target = tmp_path / "a.txt"
    target.write_bytes(b"hello")
    hasher = FileHasher()
    first = hasher.sha256(target)
    target.write_bytes(b"hello, world")  # size changes -> new fingerprint
    assert hasher.sha256(target) != first


def test_size_limit(tmp_path: Path) -> None:
    target = tmp_path / "big.bin"
    target.write_bytes(b"x" * 2048)
    with pytest.raises(FileTooLargeError):
        FileHasher(max_file_size=1024).sha256(target)


def test_directory_is_rejected_before_open(tmp_path: Path) -> None:
    with pytest.raises(NotARegularFileError):
        FileHasher().sha256(tmp_path)


def test_missing_file_raises_oserror(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        FileHasher().sha256(tmp_path / "nope.exe")


def test_normalize_path_is_case_insensitive_on_windows() -> None:
    if os.name == "nt":
        assert normalize_path(r"C:\Windows\System32") == normalize_path(r"c:\windows\system32")
