from __future__ import annotations

import pytest
from pydantic import ValidationError

from fixtures.fakes import minutes, process
from threatlens.core.models import FieldIssue, ProcessInfo, make_process_key
from threatlens.ui.formatting import field_or_reason, format_bytes, truncate_middle
from threatlens.utils.windows import nt_to_win32_path


def test_process_key_distinguishes_pid_reuse() -> None:
    assert make_process_key(100, minutes(0)) != make_process_key(100, minutes(1))
    assert make_process_key(4, None) == "4:0"


def test_process_info_is_immutable() -> None:
    p = process(100)
    with pytest.raises(ValidationError):
        p.name = "other.exe"  # type: ignore[misc]


def test_process_info_rejects_bad_hash_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        process(100, sha256="not-a-hash")
    with pytest.raises(ValidationError):
        process(100, surprise="field")


def test_process_info_json_round_trip() -> None:
    original = process(
        100, cmdline=("app.exe", "--flag"), unavailable={"username": FieldIssue.ACCESS_DENIED}
    )
    restored = ProcessInfo.model_validate_json(original.model_dump_json(exclude={"process_key"}))
    assert restored == original
    assert original.model_dump(mode="json")["process_key"] == original.process_key


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, "-"), (512, "512 B"), (1536, "1.5 KB"), (5 * 1024**3, "5.0 GB")],
)
def test_format_bytes(value: int | None, expected: str) -> None:
    assert format_bytes(value) == expected


def test_truncate_middle_keeps_file_name() -> None:
    path = r"C:\Users\someone\AppData\Local\Programs\Something\Deep\tool.exe"
    short = truncate_middle(path, 30)
    assert len(short) == 30 and short.endswith("tool.exe") and "…" in short
    assert truncate_middle("short", 30) == "short"


def test_field_or_reason_explains_missing_values() -> None:
    p = process(100, username=None, unavailable={"username": FieldIssue.ACCESS_DENIED})
    assert field_or_reason(p, "username", None) == ("<access denied>", True)
    assert field_or_reason(p, "exe", p.exe) == (p.exe, False)


DEVICES = {r"\device\harddiskvolume3": "C:", r"\device\harddiskvolume7": "D:"}


@pytest.mark.parametrize(
    ("nt_path", "expected"),
    [
        (r"\Device\HarddiskVolume3\Windows\System32\lsass.exe", r"C:\Windows\System32\lsass.exe"),
        (r"\Device\HarddiskVolume7\tools\x.exe", r"D:\tools\x.exe"),
        (r"\Device\Mup\server\share\app.exe", r"\\server\share\app.exe"),
        (r"\Device\HarddiskVolume30\x.exe", None),  # must not match volume 3 by prefix
        ("Registry", "Registry"),
    ],
)
def test_nt_to_win32_path(nt_path: str, expected: str | None) -> None:
    assert nt_to_win32_path(nt_path, DEVICES) == expected
