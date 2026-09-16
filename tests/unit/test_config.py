from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.config import (
    DEFAULT_CONFIG_TOML,
    MAX_CONFIG_BYTES,
    Config,
    load_config,
    parse_config,
    write_default_config,
)
from threatlens.errors import ConfigError

SRC = Path("config.toml")


def test_empty_config_gives_safe_defaults() -> None:
    config = parse_config("", SRC)
    assert config == Config()
    assert config.process.redact_command_lines is True
    assert config.response.require_confirmation is True
    assert "lsass.exe" in config.response.protected_processes
    assert config.retention.event_days == 7


def test_default_template_matches_builtin_defaults() -> None:
    assert parse_config(DEFAULT_CONFIG_TOML, SRC) == Config()


def test_valid_overrides() -> None:
    config = parse_config(
        "[general]\nrefresh_interval_seconds = 5\n[retention]\nevent_days = 30\n", SRC
    )
    assert config.general.refresh_interval_seconds == 5
    assert config.retention.event_days == 30


@pytest.mark.parametrize(
    "text",
    [
        "[general]\nrefresh_interval = 2\n",  # typo'd key
        "[unknown_section]\n",
        "[general]\nrefresh_interval_seconds = 0.01\n",  # would poll aggressively
        "[retention]\nevent_days = -1\n",
        "[general]\nlog_level = 'TRACE'\n",
        "[detection]\ndisabled_rules = ['proc-1']\n",
        "[detection]\ntrusted_paths = ['relative\\\\dir']\n",
        "[response]\nprotected_processes = ['..\\\\evil']\n",
        "not = [valid toml",
    ],
)
def test_invalid_config_is_rejected(text: str) -> None:
    with pytest.raises(ConfigError):
        parse_config(text, SRC)


def test_environment_variables_expand_in_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WS_TEST_ROOT", r"D:\Data")
    config = parse_config("[general]\ndatabase_path = '%WS_TEST_ROOT%\\ws.db'\n", SRC)
    assert config.general.database_path == r"D:\Data\ws.db"


def test_unresolved_environment_variable_is_rejected() -> None:
    with pytest.raises(ConfigError):
        parse_config("[general]\ndatabase_path = '%WS_DEFINITELY_UNSET_VAR%\\ws.db'\n", SRC)


def test_env_log_level_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("THREATLENS_LOG_LEVEL", "debug")
    assert parse_config("", SRC).general.log_level == "DEBUG"


def test_missing_default_file_uses_defaults(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("THREATLENS_CONFIG", raising=False)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    config, path, loaded = load_config(None)
    assert config == Config() and loaded is False
    assert path == tmp_path / "ThreatLens" / "config.toml"


def test_missing_explicit_file_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.toml")


def test_oversized_file_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "huge.toml"
    target.write_text("#" * (MAX_CONFIG_BYTES + 1), encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config(target)


def test_write_default_config_refuses_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "sub" / "config.toml"
    write_default_config(target)
    assert load_config(target)[0] == Config()
    with pytest.raises(ConfigError):
        write_default_config(target)
    write_default_config(target, force=True)
