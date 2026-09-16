from __future__ import annotations

import pytest

from threatlens.security.redaction import REDACTED, redact_command_line


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["app.exe", "--password", "hunter2"], ["app.exe", "--password", REDACTED]),
        (["app.exe", "/Password", "hunter2"], ["app.exe", "/Password", REDACTED]),
        (["app.exe", "--password=hunter2"], ["app.exe", f"--password={REDACTED}"]),
        (["app.exe", "/token:abc123"], ["app.exe", f"/token:{REDACTED}"]),
        (["app.exe", "--api-key", "k"], ["app.exe", "--api-key", REDACTED]),
        (
            ["curl.exe", "-H", "Authorization: Bearer eyJhbGciOi.xyz"],
            ["curl.exe", "-H", f"Authorization: Bearer {REDACTED}"],
        ),
        (
            ["git.exe", "clone", "https://bob:s3cret@host/repo"],
            ["git.exe", "clone", f"https://bob:{REDACTED}@host/repo"],
        ),
        (
            ["app.exe", "Server=db;User=sa;Password=p@ss;"],
            ["app.exe", f"Server=db;User=sa;Password={REDACTED};"],
        ),
    ],
)
def test_secrets_are_redacted(argv: list[str], expected: list[str]) -> None:
    assert redact_command_line(argv) == tuple(expected)


@pytest.mark.parametrize(
    "argv",
    [
        ["python.exe", "-m", "http.server", "8000"],
        ["server.exe", "-p", "8080"],  # -p is ambiguous (port) and deliberately untouched
        ["app.exe", "--password-file", r"C:\secrets\pw.txt"],  # a path, not the secret
        ["powershell.exe", "-EncodedCommand", "SQBFAFgA"],  # detection evidence must survive
        ["app.exe", "--keyboard-layout", "us"],
    ],
)
def test_non_secrets_are_untouched(argv: list[str]) -> None:
    assert redact_command_line(argv) == tuple(argv)


def test_trailing_flag_without_value_is_safe() -> None:
    assert redact_command_line(["app.exe", "--password"]) == ("app.exe", "--password")
