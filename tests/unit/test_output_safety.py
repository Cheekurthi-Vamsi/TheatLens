"""Attacker-controlled strings (process names, paths, command lines) must not be able to forge
log records, restyle terminal output, or inject terminal escape sequences."""

from __future__ import annotations

import io
import json
import logging

from rich.console import Console

from fixtures.fakes import process
from threatlens.logging_config import SafeFormatter, sanitize_log_value
from threatlens.ui.formatting import sanitize_display
from threatlens.ui.json_output import envelope, write_json
from threatlens.ui.process_views import process_table


def test_sanitize_log_value_escapes_control_characters() -> None:
    assert sanitize_log_value("a\nb\rc\td\x1b[31m") == "a\\nb\\rc\\td\\x1b[31m"


def test_log_record_cannot_be_split_by_process_name() -> None:
    record = logging.LogRecord(
        "threatlens.test",
        logging.INFO,
        __file__,
        1,
        "event=PROCESS_STARTED name=%s",
        ("evil.exe\n2026-01-01T00:00:00Z INFO event=ALL_CLEAR",),
        None,
    )
    output = SafeFormatter().format(record)
    assert "\n" not in output
    assert "\\n2026-01-01" in output


def render(console_width: int = 200, **overrides: object) -> str:
    buffer = io.StringIO()
    console = Console(
        file=buffer, width=console_width, force_terminal=True, color_system="truecolor"
    )
    console.print(process_table([process(1234, **overrides)]))
    return buffer.getvalue()


def test_rich_markup_in_process_name_is_rendered_literally() -> None:
    output = render(name="[bold red]ALL CLEAR[/bold red].exe")
    assert "[bold red]ALL CLEAR[/bold red].exe" in output


def test_terminal_escape_sequences_are_neutralised_but_visible() -> None:
    output = render(name="a\x1b]0;pwned\x07b.exe")
    assert "\x1b]0;pwned" not in output
    assert "\x07" not in output
    assert "a\\x1b]0;pwned\\x07b.exe" in output  # the analyst still sees something was there


def test_bidi_override_cannot_disguise_extension() -> None:
    output = render(name="invoice‮txt.exe")
    assert "‮" not in output
    assert "invoice\\u202etxt.exe" in output


def test_sanitize_display_leaves_normal_unicode_alone() -> None:
    assert sanitize_display("résumé-工具.exe") == "résumé-工具.exe"


def test_json_output_escapes_non_ascii_and_controls() -> None:
    buffer = io.StringIO()
    write_json(envelope("test", name="évil‮.exe\n"), buffer)
    text = buffer.getvalue()
    assert text.isascii()
    assert json.loads(text)["name"] == "évil‮.exe\n"
