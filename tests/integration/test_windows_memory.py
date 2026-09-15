"""Integration test: EmptyWorkingSet really trims a spawned child that touched memory."""

from __future__ import annotations

import subprocess
import sys
import time

import psutil
import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    from winsentinel.utils.windows import empty_working_set

PYTHON = getattr(sys, "_base_executable", sys.executable)
# Allocate and touch ~64 MB so it is resident, then idle.
CHILD = (
    "import time; b = bytearray(64 * 1024 * 1024); b[::4096] = b'x' * len(b[::4096]); "
    "print('ready', flush=True); time.sleep(60)"
)


def test_empty_working_set_shrinks_resident_memory() -> None:
    proc = subprocess.Popen([PYTHON, "-c", CHILD], stdout=subprocess.PIPE, text=True)
    try:
        assert proc.stdout is not None and proc.stdout.readline().strip() == "ready"
        child = psutil.Process(proc.pid)
        before = child.memory_info().rss
        assert before > 60 * 1024 * 1024

        empty_working_set(proc.pid)
        time.sleep(0.2)

        after = child.memory_info().rss
        assert after < before // 2, (before, after)
        assert proc.poll() is None  # trimming never kills or pauses the process
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_empty_working_set_on_missing_process_raises() -> None:
    with pytest.raises(OSError):
        empty_working_set(4_000_000)  # PIDs are multiples of 4 well below this; never exists
