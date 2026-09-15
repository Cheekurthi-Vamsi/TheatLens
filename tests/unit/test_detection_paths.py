from __future__ import annotations

import pytest

from fixtures.detection import CONTEXT
from winsentinel.detection.catalog import suspicious_parent_child
from winsentinel.detection.paths import PathClassifier, PathContext, is_under, normalize

paths = PathClassifier(CONTEXT)


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        (r"C:\Users\Bob\AppData\Local\Temp\a.exe", "a user's Temp directory"),
        (r"c:\windows\temp\a.exe", "the Windows Temp directory"),
        (r"C:\Windows\SystemTemp\a.exe", "the Windows Temp directory"),
        (r"C:\Users\Bob\AppData\Local\Temporary Internet Files\a.exe", None),
        (r"C:\Program Files\App\temp\a.exe", None),
    ],
)
def test_temp_location(path: str, expected: str | None) -> None:
    assert paths.temp_location(path) == expected


def test_current_user_temp_from_environment() -> None:
    custom = PathClassifier(PathContext(temp_dirs=(normalize(r"D:\Scratch"),)))
    assert custom.temp_location(r"D:\Scratch\a.exe") == "the current user's %TEMP% directory"


@pytest.mark.parametrize(
    ("path", "writable"),
    [
        (r"C:\Users\Bob\Downloads\a.exe", True),
        (r"C:\Users\Public\a.exe", True),
        (r"C:\ProgramData\Evil\a.exe", True),
        (r"C:\Windows\Tasks\a.exe", True),
        (r"C:\Windows\System32\spool\drivers\color\a.exe", True),
        (r"C:\$Recycle.Bin\S-1-5-21\a.exe", True),
        (r"C:\Tools\a.exe", True),  # new top-level folders are user-creatable by default
        (r"C:\Windows\System32\cmd.exe", False),
        (r"C:\Program Files (x86)\App\a.exe", False),
    ],
)
def test_user_writable_location(path: str, writable: bool) -> None:
    assert (paths.user_writable_location(path) is not None) is writable


@pytest.mark.parametrize(
    ("path", "trusted"),
    [
        (r"C:\Program Files\App\a.exe", True),
        (r"c:\WINDOWS\system32\svchost.exe", True),
        (
            r"C:\Windows\System32\spool\drivers\color\a.exe",
            False,
        ),  # writable hole inside a trusted path
        (r"C:\Program Files Evil\a.exe", False),  # prefix trick
        (r"C:\Windows\explorer.exe", False),  # Windows root is not in the default trusted list
    ],
)
def test_is_trusted(path: str, trusted: bool) -> None:
    assert paths.is_trusted(path) is trusted


def test_is_under_requires_separator_boundary() -> None:
    assert is_under(r"C:\Program Files\x.exe", r"C:\Program Files")
    assert not is_under(r"C:\Program FilesX\x.exe", r"C:\Program Files")


def test_suspicious_parent_child_is_case_insensitive() -> None:
    assert suspicious_parent_child("WINWORD.EXE", "PowerShell.exe") is not None
    assert suspicious_parent_child("explorer.exe", "powershell.exe") is None
