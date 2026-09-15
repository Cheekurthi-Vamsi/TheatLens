"""Executable location classification for detection rules.

Windows' default ACLs make only a few locations writable **exclusively by administrators**:
``%SystemRoot%`` (with notable exceptions) and ``%ProgramFiles%`` / ``%ProgramFiles(x86)%``.
Nearly everything else — user profiles, ``%ProgramData%``, and new top-level folders on the system
drive — can be written by standard users, which is why malware lives there.

The exceptions *inside* ``C:\\Windows`` matter: ``Tasks``, ``Temp``, ``Tracing``,
``System32\\spool\\drivers\\color`` and a few others are writable by standard users and are
well-known places to hide a payload under a trustworthy-looking path.

Limitations (documented, deliberate):
    * Classification is by path, not by querying the actual ACL. A custom ACL (e.g. a locked-down
      ``D:\\Tools``) is not detected; such findings are therefore labelled *inferred*.
    * Paths are compared case-insensitively after normalization; 8.3 short names are not
      expanded.
"""

from __future__ import annotations

import ntpath
import os
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Final


def normalize(path: str) -> str:
    """Case-folded, separator-normalized Windows path (works on any host OS via ``ntpath``)."""
    return ntpath.normcase(ntpath.normpath(path.strip()))


def is_under(path: str, root: str) -> bool:
    normalized_root = normalize(root).rstrip("\\")
    return normalize(path).startswith(normalized_root + "\\")


_USER_TEMP: Final = re.compile(r"^[a-z]:\\users\\[^\\]+\\appdata\\local\\temp\\")
_USER_PROFILE: Final = re.compile(r"^[a-z]:\\users\\([^\\]+)\\")
_RECYCLE_BIN: Final = re.compile(r"^[a-z]:\\\$recycle\.bin\\")

# Standard-user-writable subdirectories of %SystemRoot% (relative, lowercase).
WRITABLE_WINDOWS_SUBDIRS: Final = (
    "temp",
    "tasks",
    "tracing",
    "registration\\crmlog",
    "system32\\tasks",
    "system32\\spool\\drivers\\color",
    "system32\\spool\\printers",
    "system32\\microsoft\\crypto\\rsa\\machinekeys",
    "system32\\com\\dmp",
    "syswow64\\tasks",
    "syswow64\\com\\dmp",
)


@dataclass(frozen=True, slots=True)
class PathContext:
    system_root: str = r"c:\windows"
    program_files: tuple[str, ...] = (r"c:\program files", r"c:\program files (x86)")
    temp_dirs: tuple[str, ...] = ()
    trusted_paths: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def from_environment(cls, trusted_paths: Iterable[str]) -> PathContext:
        system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
        program_files = tuple(
            normalize(value)
            for value in {
                os.environ.get("PROGRAMFILES") or r"C:\Program Files",
                os.environ.get("PROGRAMFILES(X86)") or r"C:\Program Files (x86)",
                os.environ.get("PROGRAMW6432") or r"C:\Program Files",
            }
        )
        temp_dirs = tuple(
            normalize(value) for value in {os.environ.get("TEMP"), os.environ.get("TMP")} if value
        )
        return cls(
            system_root=normalize(system_root),
            program_files=program_files,
            temp_dirs=temp_dirs,
            trusted_paths=tuple(normalize(p) for p in trusted_paths),
        )


class PathClassifier:
    def __init__(self, context: PathContext) -> None:
        self._ctx = context
        root = normalize(context.system_root)
        self._system_root = root
        self._writable_windows = tuple(f"{root}\\{sub}" for sub in WRITABLE_WINDOWS_SUBDIRS)

    @property
    def system_root(self) -> str:
        return self._system_root

    def temp_location(self, path: str) -> str | None:
        """Return a label if ``path`` is inside a temporary directory."""
        p = normalize(path)
        if _USER_TEMP.match(p):
            return "a user's Temp directory"
        if any(p.startswith(temp.rstrip("\\") + "\\") for temp in self._ctx.temp_dirs):
            return "the current user's %TEMP% directory"
        if is_under(p, f"{self._system_root}\\temp") or is_under(
            p, f"{self._system_root}\\systemtemp"
        ):
            return "the Windows Temp directory"
        return None

    def user_writable_location(self, path: str) -> str | None:
        """Return a label if ``path`` is (by default ACLs) writable by standard users."""
        p = normalize(path)
        if temp := self.temp_location(p):
            return temp
        if any(is_under(p, writable) for writable in self._writable_windows):
            return "a standard-user-writable folder inside the Windows directory"
        if _RECYCLE_BIN.match(p):
            return "the Recycle Bin"
        if match := _USER_PROFILE.match(p):
            profile = match.group(1)
            return "the Public user profile" if profile == "public" else "a user profile directory"
        if is_under(p, self._system_root) or any(is_under(p, pf) for pf in self._ctx.program_files):
            return None
        if re.match(r"^[a-z]:\\programdata\\", p):
            return "the ProgramData directory"
        return "a directory outside the administrator-protected install locations"

    def is_trusted(self, path: str) -> bool:
        """Under a configured trusted path *and* not in a user-writable exception within it."""
        p = normalize(path)
        if not any(is_under(p, trusted) for trusted in self._ctx.trusted_paths):
            return False
        return not any(is_under(p, writable) for writable in self._writable_windows)

    def directory_of(self, path: str) -> str:
        return ntpath.dirname(normalize(path))
