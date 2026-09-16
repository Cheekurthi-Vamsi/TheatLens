"""End-to-end detection on real Windows data with benign stand-ins for attacker techniques.

* A copy of Windows' own PING.EXE renamed to svchost.exe / invoice.pdf.exe, run from pytest's
  temp directory, pinging only 127.0.0.1.
* PowerShell with an -EncodedCommand whose script is ``Start-Sleep``.

Nothing leaves the machine; files live in pytest's tmp_path and are removed by pytest.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    from threatlens.collectors.network_collector import NetworkCollector
    from threatlens.collectors.process_collector import ProcessCollector, ProcessEnricher
    from threatlens.config import Config
    from threatlens.core.models import DetectionResult, ProcessInfo
    from threatlens.correlation.process_network import correlate, lookup_from_processes
    from threatlens.detection.scan import scan_process
    from threatlens.detection.settings import DetectionSettings
    from threatlens.utils.time import utc_now

PING = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "PING.EXE"


def _wait_for(pid: int, need_cmdline: bool = False) -> tuple[ProcessInfo, list[ProcessInfo]]:
    collector = ProcessCollector()
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        processes = list(collector.collect().processes)
        target = next((p for p in processes if p.pid == pid), None)
        if target is not None and (target.cmdline or not need_cmdline):
            return target, processes
        time.sleep(0.1)
    raise AssertionError(f"PID {pid} not observed")


def _scan(pid: int, need_cmdline: bool = False) -> list[DetectionResult]:
    target, processes = _wait_for(pid, need_cmdline)
    target = ProcessEnricher().enrich(target)
    processes = [target if p.process_key == target.process_key else p for p in processes]
    sockets = correlate(NetworkCollector().collect().connections, lookup_from_processes(processes))
    settings = DetectionSettings.from_config(Config())
    return scan_process(target, processes, sockets, settings, now=utc_now())


@pytest.fixture
def run_copy(tmp_path: Path) -> Iterator[object]:
    started: list[subprocess.Popen[bytes]] = []

    def start(name: str) -> subprocess.Popen[bytes]:
        copy = tmp_path / name
        shutil.copy2(PING, copy)
        proc = subprocess.Popen([str(copy), "-n", "15", "127.0.0.1"], stdout=subprocess.DEVNULL)
        started.append(proc)
        return proc

    yield start
    for proc in started:
        proc.kill()
        proc.wait(timeout=10)


def test_masquerading_system_binary_in_temp_is_detected(run_copy: object) -> None:
    if "\\temp\\" not in str(Path(os.environ["TEMP"])).lower() + "\\":
        pytest.skip("TEMP is not a standard Temp directory")
    proc = run_copy("svchost.exe")  # type: ignore[operator]
    results = {r.rule_id: r for r in _scan(proc.pid)}
    assert "PROC-005" in results
    assert "PROC-001" in results
    # Catalog signature still verifies for the copy, so PROC-002 (unsigned) must NOT fire.
    assert "PROC-002" not in results


def test_double_extension_name_is_detected(run_copy: object) -> None:
    proc = run_copy("invoice.pdf.exe")  # type: ignore[operator]
    assert "PROC-008" in {r.rule_id for r in _scan(proc.pid)}


def test_encoded_powershell_is_detected_and_decoded() -> None:
    script = base64.b64encode("Start-Sleep -Seconds 10".encode("utf-16-le")).decode()
    proc = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", script],
        stdout=subprocess.DEVNULL,
    )
    try:
        results = [r for r in _scan(proc.pid, need_cmdline=True) if r.rule_id == "PROC-006"]
    finally:
        proc.kill()
        proc.wait(timeout=10)
    assert results
    decoded = [e.value for e in results[0].evidence if e.field == "decoded_command"]
    assert decoded == ["Start-Sleep -Seconds 10"]


def test_genuine_system_processes_produce_no_masquerading_findings() -> None:
    collector = ProcessCollector()
    processes = list(collector.collect().processes)
    settings = DetectionSettings.from_config(Config())
    genuine = [
        p for p in processes if p.name.lower() in {"svchost.exe", "wmiprvse.exe", "explorer.exe"}
    ]
    assert genuine
    for process in genuine:
        findings = scan_process(process, processes, [], settings, now=utc_now())
        assert "PROC-005" not in {f.rule_id for f in findings}, process.exe
