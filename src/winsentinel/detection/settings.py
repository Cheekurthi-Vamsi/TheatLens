"""Detection settings derived from configuration and the environment (built once, immutable)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta

from winsentinel.config import Config
from winsentinel.detection.paths import PathClassifier, PathContext, normalize


@dataclass(frozen=True, slots=True)
class DetectionSettings:
    paths: PathClassifier
    correlation_window: timedelta = timedelta(seconds=10)
    burst_window: timedelta = timedelta(seconds=60)
    burst_threshold: int = 40
    fanout_threshold: int = 20
    failed_connection_threshold: int = 15
    common_remote_ports: frozenset[int] = field(default_factory=frozenset)
    disabled_rules: frozenset[str] = field(default_factory=frozenset)
    ignored_executables: frozenset[str] = field(default_factory=frozenset)

    @classmethod
    def from_config(cls, config: Config, context: PathContext | None = None) -> DetectionSettings:
        detection = config.detection
        return cls(
            paths=PathClassifier(context or PathContext.from_environment(detection.trusted_paths)),
            correlation_window=timedelta(seconds=detection.correlation_window_seconds),
            burst_window=timedelta(seconds=detection.network_burst_window_seconds),
            burst_threshold=detection.network_burst_threshold,
            fanout_threshold=detection.network_fanout_threshold,
            failed_connection_threshold=detection.failed_connection_threshold,
            common_remote_ports=frozenset(detection.common_remote_ports),
            disabled_rules=frozenset(detection.disabled_rules),
            ignored_executables=frozenset(normalize(p) for p in detection.ignored_executables),
        )
