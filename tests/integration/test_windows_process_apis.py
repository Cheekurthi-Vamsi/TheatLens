"""Integration tests against real Windows APIs.

Every process these tests observe is one they spawn themselves: a benign Python interpreter that
sleeps. ``sys._base_executable`` is used because a venv's ``python.exe`` is a redirector that
would add an extra launcher process to the tree.
"""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
import time
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    from threatlens.collectors.process_collector import ProcessCollector, ProcessEnricher
    from threatlens.core.models import (
        Architecture,
        EventType,
        IntegrityLevel,
        ProcessInfo,
        SignatureSource,
        SignatureStatus,
    )
    from threatlens.correlation.process_tree import build_process_tree, find_node
    from threatlens.monitors.process_monitor import ProcessMonitor
    from threatlens.security.privileges import detect_privileges
    from threatlens.security.redaction import REDACTED
    from threatlens.security.signatures import SignatureVerifier
    from threatlens.utils import ntapi, windows

PYTHON = getattr(sys, "_base_executable", sys.executable)
SPAWN_TIMEOUT_SECONDS = 10.0


def spawn_sleeper(*extra_args: str) -> subprocess.Popen[bytes]:
    marker = f"threatlens-test-{uuid.uuid4().hex}"
    return subprocess.Popen(
        [PYTHON, "-c", "import time, sys; time.sleep(60)", marker, *extra_args],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


@pytest.fixture
def child() -> Iterator[subprocess.Popen[bytes]]:
    proc = spawn_sleeper("--password", "hunter2")
    try:
        yield proc
    finally:
        proc.kill()
        proc.wait(timeout=SPAWN_TIMEOUT_SECONDS)


def wait_for(collector: ProcessCollector, pid: int) -> ProcessInfo:
    deadline = time.monotonic() + SPAWN_TIMEOUT_SECONDS
    while time.monotonic() < deadline:
        found = collector.collect().by_pid().get(pid)
        # The command line of a just-created process can be empty for a moment.
        if found is not None and found.cmdline:
            return found
        time.sleep(0.1)
    raise AssertionError(
        f"PID {pid} not observed with a command line within {SPAWN_TIMEOUT_SECONDS}s"
    )


class TestStructureLayout:
    def test_x64_structure_sizes_match_windows_headers(self) -> None:
        if sys.maxsize <= 2**32:
            pytest.skip("layout assertions are for 64-bit Python")
        assert ctypes.sizeof(ntapi.SystemProcessInformation) == 256
        assert ctypes.sizeof(ntapi.SystemThreadInformation) == 80


class TestBulkEnumeration:
    def test_own_process_identity(self) -> None:
        entries = {e.pid: e for e in ntapi.SystemProcessQuery().query()}
        me = entries[os.getpid()]
        assert me.ppid == os.getppid()
        assert me.image_name.lower() == Path(PYTHON).name.lower()
        assert me.num_threads >= 1
        assert me.working_set > 0
        assert abs(me.create_time_epoch - time.time()) < 24 * 3600
        assert 0 in entries and 4 in entries  # Idle and System are always present

    def test_image_name_by_pid_without_handle(self) -> None:
        nt_path = ntapi.query_image_name_by_pid(os.getpid())
        assert nt_path.lower().startswith("\\device\\")
        resolved = windows.DevicePathResolver().to_win32(nt_path)
        assert resolved is not None
        assert os.path.samefile(resolved, PYTHON)

    def test_image_name_for_nonexistent_pid_raises(self) -> None:
        with pytest.raises(OSError):
            ntapi.query_image_name_by_pid(0xFFFFFFF0)


class TestCollector:
    def test_spawned_child_is_fully_observed(self, child: subprocess.Popen[bytes]) -> None:
        info = wait_for(ProcessCollector(), child.pid)
        assert info.ppid == os.getpid()
        assert info.exe is not None and os.path.samefile(info.exe, PYTHON)
        assert info.cmdline is not None and info.cmdline[-2:] == ("--password", REDACTED)
        assert "hunter2" not in " ".join(info.cmdline)
        assert info.username is not None
        assert info.username.lower().endswith("\\" + os.environ["USERNAME"].lower())
        expected_integrity = (
            IntegrityLevel.HIGH if detect_privileges().elevated else IntegrityLevel.MEDIUM
        )
        assert info.integrity_level is expected_integrity
        if sys.maxsize > 2**32:
            assert info.architecture in (Architecture.X64, Architecture.ARM64)
        my_session = {e.pid: e.session_id for e in ntapi.SystemProcessQuery().query()}[os.getpid()]
        assert info.session_id == my_session  # a child inherits its parent's session
        assert info.suspended is False
        assert "exe" not in info.unavailable and "cmdline" not in info.unavailable

    def test_system_process_exe_visible_even_without_admin(self) -> None:
        snapshot = ProcessCollector().collect()
        smss = [p for p in snapshot.processes if p.name.lower() == "smss.exe"]
        assert smss, "smss.exe should always be running"
        assert smss[0].exe is not None and smss[0].exe.lower().endswith(r"\system32\smss.exe")

    def test_cpu_is_sampled_on_second_snapshot(self, child: subprocess.Popen[bytes]) -> None:
        collector = ProcessCollector()
        first = collector.collect().by_pid()[os.getpid()]
        assert first.cpu_percent is None
        sum(i * i for i in range(300_000))  # burn a little CPU
        second = collector.collect().by_pid()[os.getpid()]
        assert second.cpu_percent is not None and 0.0 <= second.cpu_percent <= 100.0

    def test_suspend_is_detected_and_emits_change_event(
        self, child: subprocess.Popen[bytes]
    ) -> None:
        import psutil

        collector = ProcessCollector()
        monitor = ProcessMonitor(collector)
        wait_for(collector, child.pid)
        monitor.poll()
        target = psutil.Process(child.pid)
        target.suspend()
        try:
            events = monitor.poll()
            assert collector.collect().by_pid()[child.pid].suspended is True
        finally:
            target.resume()
        changed = [
            e for e in events if e.event_type is EventType.PROCESS_CHANGED and e.pid == child.pid
        ]
        assert changed and changed[0].data["changed"]["suspended"] == [False, True]

    def test_process_start_and_stop_detected(self) -> None:
        monitor = ProcessMonitor(ProcessCollector())
        monitor.poll()  # inventory
        proc = spawn_sleeper()
        try:
            deadline = time.monotonic() + SPAWN_TIMEOUT_SECONDS
            started = []
            while not started and time.monotonic() < deadline:
                started = [
                    e
                    for e in monitor.poll()
                    if e.event_type is EventType.PROCESS_STARTED and e.pid == proc.pid
                ]
            assert started, "PROCESS_STARTED not observed"
            assert started[0].data["parent_key"] is not None
        finally:
            proc.kill()
            proc.wait(timeout=SPAWN_TIMEOUT_SECONDS)
        stopped = [
            e
            for e in monitor.poll()
            if e.event_type is EventType.PROCESS_STOPPED and e.pid == proc.pid
        ]
        assert stopped and stopped[0].process_key == started[0].process_key

    def test_child_appears_under_this_process_in_tree(self, child: subprocess.Popen[bytes]) -> None:
        collector = ProcessCollector()
        wait_for(collector, child.pid)
        snapshot = collector.collect()
        me = find_node(build_process_tree(snapshot.processes), os.getpid())
        assert me is not None
        assert child.pid in {c.process.pid for c in me.children}


class TestSignatures:
    def test_embedded_signature_valid(self) -> None:
        result = SignatureVerifier().verify(os.path.join(os.environ["SYSTEMROOT"], "explorer.exe"))
        assert result.status is SignatureStatus.VALID
        assert result.signer

    def test_catalog_signature_valid(self) -> None:
        notepad = Path(os.environ["SYSTEMROOT"]) / "System32" / "notepad.exe"
        if not notepad.exists():
            pytest.skip("notepad.exe not present")
        result = SignatureVerifier().verify(str(notepad))
        assert result.status is SignatureStatus.VALID
        assert result.source in (SignatureSource.CATALOG, SignatureSource.EMBEDDED)

    def test_unsigned_file(self, tmp_path: Path) -> None:
        fake = tmp_path / "unsigned.exe"
        fake.write_bytes(b"MZ" + b"\x00" * 1022)
        assert SignatureVerifier().verify(str(fake)).status is SignatureStatus.UNSIGNED

    def test_tampered_signed_binary_is_invalid(self, tmp_path: Path) -> None:
        """Flip one byte inside a signed binary: the Authenticode digest must no longer match."""
        original = Path(PYTHON)
        if SignatureVerifier().verify(str(original)).source is not SignatureSource.EMBEDDED:
            pytest.skip("interpreter is not embedded-signed")
        data = bytearray(original.read_bytes())
        data[len(data) // 3] ^= 0xFF
        tampered = tmp_path / "tampered.exe"
        tampered.write_bytes(bytes(data))
        result = SignatureVerifier().verify(str(tampered))
        assert result.status is SignatureStatus.INVALID
        assert result.signer is None  # never show a publisher from an untrusted signature

    def test_enricher_populates_hash_and_signature(self, child: subprocess.Popen[bytes]) -> None:
        collector = ProcessCollector()
        info = ProcessEnricher().enrich(wait_for(collector, child.pid))
        assert info.sha256 is not None and len(info.sha256) == 64
        assert info.signature is not None


class TestPrivilegesAndVersion:
    def test_privilege_detection_works(self) -> None:
        assert detect_privileges().detection_failed is False

    def test_windows_version(self) -> None:
        version = windows.get_windows_version()
        assert version.major == 10 and version.is_supported

    def test_split_command_line_matches_msvcrt_rules(self) -> None:
        assert windows.split_command_line(
            r'"C:\Program Files\a b\x.exe" -f "quoted arg" plain'
        ) == [
            r"C:\Program Files\a b\x.exe",
            "-f",
            "quoted arg",
            "plain",
        ]
        assert windows.split_command_line("") == []
