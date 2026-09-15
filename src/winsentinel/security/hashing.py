"""SHA256 file hashing with a fingerprint-validated cache.

SHA256 is the primary identity for executables throughout WinSentinel (allowlists, baselines,
detections). Hashing is I/O-bound, so we:

* cache results keyed by ``(normalized path, size, mtime_ns)`` — if any of these change the entry
  is simply never hit again;
* refuse files larger than a configurable limit (``FileTooLargeError``) rather than stall a
  collector on a multi-GB binary;
* refuse non-regular files (named pipes, devices) *before* opening them, since opening a device
  path can block indefinitely;
* re-check the fingerprint via ``fstat`` on the open handle after hashing, and do not cache a
  hash of a file that changed while being read (TOCTOU).
"""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Final

from winsentinel.utils.lru import BoundedLRUCache

DEFAULT_MAX_FILE_SIZE: Final = 256 * 1024 * 1024
DEFAULT_CACHE_ENTRIES: Final = 4096
CHUNK_SIZE: Final = 1024 * 1024


class FileTooLargeError(Exception):
    """The file exceeds the configured hashing size limit."""

    def __init__(self, path: str, size: int, limit: int) -> None:
        super().__init__(f"{path} is {size} bytes; hashing limit is {limit} bytes")
        self.size = size
        self.limit = limit


class NotARegularFileError(Exception):
    """The path is a directory, device, pipe or other non-regular file."""


@dataclass(frozen=True, slots=True)
class FileFingerprint:
    path: str
    size: int
    mtime_ns: int

    @classmethod
    def from_stat(cls, path: str, st: os.stat_result) -> FileFingerprint:
        return cls(normalize_path(path), st.st_size, st.st_mtime_ns)


def normalize_path(path: str | os.PathLike[str]) -> str:
    """Canonical form for cache keys and comparisons: absolute, case-folded, native separators.

    NTFS is case-insensitive by default, so ``C:\\Windows`` and ``c:\\windows`` are the same file.
    """
    # abspath, not Path.resolve(): resolve() follows junctions/symlinks, but the identity we want
    # is the path as the process or user referenced it.
    return os.path.normcase(os.path.abspath(os.fspath(path)))  # noqa: PTH100


def fingerprint(path: str | os.PathLike[str]) -> FileFingerprint:
    """Stat a path and return its fingerprint. Raises ``OSError`` / ``NotARegularFileError``."""
    raw = os.fspath(path)
    st = Path(raw).stat()
    if not stat.S_ISREG(st.st_mode):
        raise NotARegularFileError(raw)
    return FileFingerprint.from_stat(raw, st)


class FileHasher:
    """Thread-safe SHA256 hasher with bounded cache."""

    def __init__(
        self,
        max_file_size: int = DEFAULT_MAX_FILE_SIZE,
        cache_entries: int = DEFAULT_CACHE_ENTRIES,
    ) -> None:
        if max_file_size < 1:
            raise ValueError("max_file_size must be positive")
        self._max_file_size = max_file_size
        self._cache: BoundedLRUCache[FileFingerprint, str] = BoundedLRUCache(cache_entries)

    @property
    def cache(self) -> BoundedLRUCache[FileFingerprint, str]:
        return self._cache

    def sha256(self, path: str | os.PathLike[str]) -> str:
        """Return the lowercase hex SHA256 of ``path``.

        Raises ``OSError`` (missing, access denied, sharing violation), ``NotARegularFileError``
        or ``FileTooLargeError``.
        """
        before = fingerprint(path)
        cached = self._cache.get(before)
        if cached is not None:
            return cached
        if before.size > self._max_file_size:
            raise FileTooLargeError(before.path, before.size, self._max_file_size)

        digest = hashlib.sha256()
        with Path(before.path).open("rb") as handle:
            for chunk in iter(lambda: handle.read(CHUNK_SIZE), b""):
                digest.update(chunk)
            after = FileFingerprint.from_stat(before.path, os.fstat(handle.fileno()))

        result = digest.hexdigest()
        if after == before:
            self._cache.put(before, result)
        return result
