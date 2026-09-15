"""Configuration: schema, safe defaults, and TOML loading.

Security considerations
-----------------------
* The config file is **untrusted input**. It is size-limited, parsed with the stdlib ``tomllib``
  (no code execution), validated with ``extra="forbid"`` so typos fail loudly, and every numeric
  field is range-bounded.
* Paths are expanded for ``%VAR%`` environment variables and must be absolute after expansion.
* If WinSentinel runs elevated but reads a config file writable by a standard user, a
  lower-privileged process could weaken detection (e.g. by adding allowlist entries). See
  SECURITY.md; an ACL check is planned for the phase that introduces allowlisting.

Sections not yet consumed by the running code are still validated now, so a config written
today remains valid as later phases start honouring it.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path, PureWindowsPath
from typing import Annotated, Final, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, ValidationError

from winsentinel.errors import ConfigError

CONFIG_ENV_VAR: Final = "WINSENTINEL_CONFIG"
LOG_LEVEL_ENV_VAR: Final = "WINSENTINEL_LOG_LEVEL"
MAX_CONFIG_BYTES: Final = 256 * 1024
APP_DIR_NAME: Final = "WinSentinel"


def app_data_dir() -> Path:
    """Per-user data directory: ``%LOCALAPPDATA%\\WinSentinel``.

    ``LOCALAPPDATA`` is per-user and not roaming, which suits a machine-specific security log.
    """
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
    return Path(base) / APP_DIR_NAME


def default_config_path() -> Path:
    override = os.environ.get(CONFIG_ENV_VAR)
    return Path(override) if override else app_data_dir() / "config.toml"


def _expand_absolute_path(value: str) -> str:
    if "\x00" in value:
        raise ValueError("path must not contain NUL characters")
    expanded = os.path.expandvars(value)
    if "%" in expanded:
        raise ValueError(f"unresolved environment variable in path: {value!r}")
    if not PureWindowsPath(expanded).is_absolute():
        raise ValueError(f"path must be absolute: {value!r}")
    return expanded


AbsolutePath = Annotated[str, AfterValidator(_expand_absolute_path)]
ProcessName = Annotated[str, Field(min_length=1, max_length=260, pattern=r"^[^\\/:*?\"<>|\x00]+$")]
RuleId = Annotated[str, Field(pattern=r"^[A-Z]{2,8}-\d{3}$")]


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class GeneralConfig(_Section):
    refresh_interval_seconds: float = Field(default=2.0, ge=0.5, le=60.0)
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"
    database_path: AbsolutePath | None = None
    log_path: AbsolutePath | None = None

    def resolved_database_path(self) -> Path:
        return Path(self.database_path) if self.database_path else app_data_dir() / "winsentinel.db"

    def resolved_log_path(self) -> Path:
        return Path(self.log_path) if self.log_path else app_data_dir() / "winsentinel.log"


class RetentionConfig(_Section):
    """Days to keep data; ``0`` means unlimited."""

    event_days: int = Field(default=7, ge=0, le=3650)
    alert_days: int = Field(default=90, ge=0, le=3650)
    action_days: int = Field(default=0, ge=0, le=3650)


class CollectorsConfig(_Section):
    enable_process: bool = True
    enable_network: bool = True
    enable_dns: bool = False
    enable_file_monitor: bool = True
    enable_eventlog: bool = True
    enable_persistence_monitor: bool = True
    collector_timeout_seconds: float = Field(default=10.0, ge=1.0, le=120.0)


class ProcessConfig(_Section):
    redact_command_lines: bool = True
    hash_max_file_size_mb: int = Field(default=256, ge=1, le=4096)
    verify_signatures: bool = True


class FileMonitorConfig(_Section):
    # Empty means "use safe defaults" (Startup folders, %TEMP%, Downloads) — never all of C:\.
    monitored_paths: tuple[AbsolutePath, ...] = ()


class DetectionConfig(_Section):
    alert_threshold: int = Field(default=40, ge=1, le=100)
    correlation_window_seconds: int = Field(default=10, ge=1, le=3600)
    # Trusted paths *reduce* scores; they never suppress detection. Note that some locations under
    # C:\Windows (e.g. C:\Windows\Temp, C:\Windows\Tasks) are writable by standard users.
    trusted_paths: tuple[AbsolutePath, ...] = (
        r"C:\Windows\System32",
        r"C:\Program Files",
        r"C:\Program Files (x86)",
    )
    disabled_rules: tuple[RuleId, ...] = ()
    # Matched on full executable path, not name: a name is trivially spoofed by copying a file.
    ignored_executables: tuple[AbsolutePath, ...] = ()
    # NET-003: bursts of new outbound connections from one process within the window.
    network_burst_window_seconds: int = Field(default=60, ge=5, le=3600)
    network_burst_threshold: int = Field(default=40, ge=5, le=10_000)
    network_fanout_threshold: int = Field(default=20, ge=3, le=10_000)
    failed_connection_threshold: int = Field(default=15, ge=3, le=10_000)
    # NET-004: ports considered ordinary for outbound connections.
    common_remote_ports: tuple[Annotated[int, Field(ge=1, le=65535)], ...] = (
        21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
        3478, 5222, 5223, 5228, 8080, 8443,
    )  # fmt: skip


class ResponseConfig(_Section):
    require_confirmation: bool = True
    # Critical Windows processes. Terminating these crashes (BSOD) or logs off the system.
    protected_processes: tuple[ProcessName, ...] = (
        "System",
        "Registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "winlogon.exe",
        "svchost.exe",
        "fontdrvhost.exe",
        "dwm.exe",
        "MsMpEng.exe",
    )


class BaselineConfig(_Section):
    max_age_days: int = Field(default=30, ge=1, le=365)


class EngineConfig(_Section):
    """Runtime limits for ``winsentinel monitor``. Every queue and cache is bounded."""

    event_queue_size: int = Field(default=10_000, ge=100, le=1_000_000)
    enrichment_queue_size: int = Field(default=4_096, ge=16, le=100_000)
    # Exited processes stay resolvable this long, so short-lived parents still appear in lineage.
    exit_retention_seconds: int = Field(default=300, ge=10, le=3_600)
    max_backoff_seconds: float = Field(default=60.0, ge=1.0, le=600.0)
    status_interval_seconds: float = Field(default=2.0, ge=0.5, le=60.0)
    persistence_interval_seconds: float = Field(default=30.0, ge=5.0, le=3600.0)
    shutdown_timeout_seconds: float = Field(default=5.0, ge=1.0, le=60.0)


class Config(BaseModel):
    """Root configuration object."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    general: GeneralConfig = GeneralConfig()
    retention: RetentionConfig = RetentionConfig()
    collectors: CollectorsConfig = CollectorsConfig()
    process: ProcessConfig = ProcessConfig()
    file_monitor: FileMonitorConfig = FileMonitorConfig()
    detection: DetectionConfig = DetectionConfig()
    response: ResponseConfig = ResponseConfig()
    baseline: BaselineConfig = BaselineConfig()
    engine: EngineConfig = EngineConfig()


def _format_validation_error(path: Path, error: ValidationError) -> str:
    lines = [f"Invalid configuration in {path}:"]
    for item in error.errors():
        location = ".".join(str(part) for part in item["loc"]) or "<root>"
        lines.append(f"  - {location}: {item['msg']}")
    return "\n".join(lines)


def parse_config(text: str, source: Path) -> Config:
    """Parse and validate TOML text. Raises :class:`ConfigError`."""
    try:
        raw = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{source} is not valid TOML: {exc}") from exc
    try:
        config = Config.model_validate(raw)
    except ValidationError as exc:
        raise ConfigError(_format_validation_error(source, exc)) from exc

    env_level = os.environ.get(LOG_LEVEL_ENV_VAR)
    if env_level:
        try:
            general = config.general.model_copy(update={"log_level": env_level.upper()})
            config = config.model_copy(
                update={"general": GeneralConfig.model_validate(general.model_dump())}
            )
        except ValidationError as exc:
            raise ConfigError(
                f"{LOG_LEVEL_ENV_VAR}={env_level!r} is not a valid log level"
            ) from exc
    return config


def load_config(path: Path | None = None) -> tuple[Config, Path, bool]:
    """Load configuration.

    Returns ``(config, path, loaded_from_file)``. A missing file at the *default* location yields
    safe defaults; a missing file that the user explicitly asked for is an error.
    """
    explicit = path is not None or bool(os.environ.get(CONFIG_ENV_VAR))
    target = path or default_config_path()
    try:
        size = target.stat().st_size
    except FileNotFoundError:
        if explicit:
            raise ConfigError(f"Configuration file not found: {target}") from None
        return parse_config("", target), target, False
    except OSError as exc:
        raise ConfigError(f"Cannot access configuration file {target}: {exc}") from exc

    if size > MAX_CONFIG_BYTES:
        raise ConfigError(
            f"{target} is {size} bytes; refusing configs larger than {MAX_CONFIG_BYTES}"
        )
    try:
        text = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ConfigError(f"Cannot read configuration file {target}: {exc}") from exc
    return parse_config(text, target), target, True


DEFAULT_CONFIG_TOML: Final = """\
# WinSentinel configuration. All keys are optional; values shown are the defaults.

[general]
refresh_interval_seconds = 2.0
log_level = "INFO"                 # DEBUG | INFO | WARNING | ERROR
# database_path = "%LOCALAPPDATA%\\\\WinSentinel\\\\winsentinel.db"
# log_path = "%LOCALAPPDATA%\\\\WinSentinel\\\\winsentinel.log"

[retention]                        # days; 0 = unlimited
event_days = 7
alert_days = 90
action_days = 0

[collectors]
enable_process = true
enable_network = true
enable_dns = false                 # needs the DNS-Client/Operational log enabled (admin)
enable_file_monitor = true
enable_eventlog = true
enable_persistence_monitor = true
collector_timeout_seconds = 10.0

[process]
redact_command_lines = true        # strip passwords/tokens from command lines at collection
hash_max_file_size_mb = 256
verify_signatures = true

[file_monitor]
monitored_paths = []               # empty = safe defaults (Startup folders, TEMP, Downloads)

[detection]
alert_threshold = 40
correlation_window_seconds = 10
trusted_paths = ["C:\\\\Windows\\\\System32", "C:\\\\Program Files", "C:\\\\Program Files (x86)"]
disabled_rules = []                # e.g. ["NET-004"]; see 'winsentinel rules'
ignored_executables = []           # full paths, never bare process names
network_burst_window_seconds = 60  # NET-003
network_burst_threshold = 40
network_fanout_threshold = 20
failed_connection_threshold = 15
common_remote_ports = [            # NET-004
    21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995,
    3478, 5222, 5223, 5228, 8080, 8443,
]

[response]
require_confirmation = true

[baseline]
max_age_days = 30

[engine]
event_queue_size = 10000           # bounded; oldest events are dropped (and counted) when full
enrichment_queue_size = 4096
exit_retention_seconds = 300       # keep exited processes resolvable for lineage
max_backoff_seconds = 60.0         # retry ceiling for a failing collector
status_interval_seconds = 2.0
persistence_interval_seconds = 30.0
shutdown_timeout_seconds = 5.0
"""


def write_default_config(path: Path, *, force: bool = False) -> None:
    """Create a commented default config. Refuses to overwrite unless ``force``."""
    if path.exists() and not force:
        raise ConfigError(f"{path} already exists (use --force to overwrite)")
    path.parent.mkdir(parents=True, exist_ok=True)
    # Write to a sibling temp file then atomically replace, so a crash never leaves half a config.
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(DEFAULT_CONFIG_TOML, encoding="utf-8")
    temporary.replace(path)
