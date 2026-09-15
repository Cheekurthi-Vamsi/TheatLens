"""Self-test used by ``winsentinel status``: can each data source actually produce data here?

Each check runs the real collector once, times it, and reports success or the reason for failure.
Checks never raise: a failing check is a result, not a crash.
"""

from __future__ import annotations

import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.collectors.process_collector import ProcessCollector
from winsentinel.core.models import SignatureStatus
from winsentinel.errors import ProcessNotFoundError, WinSentinelError
from winsentinel.security.signatures import SignatureVerifier


@dataclass(frozen=True, slots=True)
class CheckResult:
    name: str
    ok: bool
    duration_ms: float
    detail: str


def _timed(name: str, check: Callable[[], str]) -> CheckResult:
    start = time.perf_counter()
    try:
        detail = check()
        ok = True
    except (OSError, WinSentinelError) as exc:
        detail, ok = str(exc) or type(exc).__name__, False
    return CheckResult(name, ok, round((time.perf_counter() - start) * 1000, 1), detail)


def run_self_test(
    process_collector: ProcessCollector,
    network_collector: NetworkCollector,
    verifier: SignatureVerifier,
) -> list[CheckResult]:
    def processes() -> str:
        snapshot = process_collector.collect()
        return f"{len(snapshot.processes)} processes"

    def network() -> str:
        snapshot = network_collector.collect()
        detail = f"{len(snapshot.connections)} sockets"
        if snapshot.unavailable_tables:
            detail += f" (unavailable: {', '.join(snapshot.unavailable_tables)})"
        return detail

    def signatures() -> str:
        system_root = os.environ.get("SYSTEMROOT") or r"C:\Windows"
        target = Path(system_root) / "System32" / "kernel32.dll"
        result = verifier.verify(str(target))
        if result.status is not SignatureStatus.VALID:
            raise WinSentinelError(
                f"kernel32.dll verified as {result.status.value}: {result.detail}"
            )
        return f"kernel32.dll VALID ({result.source.value.lower()})"

    return [
        _timed("process collector", processes),
        _timed("network collector", network),
        _timed("signature verification", signatures),
    ]


def process_instance_alive(collector: ProcessCollector, pid: int, process_key: str | None) -> bool:
    """True if ``pid`` is running and (when known) is the same instance as ``process_key``."""
    try:
        info = collector.collect_pid(pid)
    except (ProcessNotFoundError, WinSentinelError):
        return False
    return process_key is None or info.process_key == process_key
