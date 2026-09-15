"""Integration test for real suspend/resume/terminate against a spawned benign child."""

from __future__ import annotations

import subprocess
import sys
import time

import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    from winsentinel.response.process_control import ProcessController, ProcessIdentityChangedError

PYTHON = getattr(sys, "_base_executable", sys.executable)


def test_suspend_resume_terminate_lifecycle() -> None:
    proc = subprocess.Popen(
        [PYTHON, "-c", "import time; time.sleep(60)"], stdout=subprocess.DEVNULL
    )
    controller = ProcessController()
    try:
        time.sleep(0.3)
        info = controller.current(proc.pid)
        assert info.suspended is False

        controller.suspend(proc.pid, info.process_key)
        time.sleep(0.3)
        assert controller.current(proc.pid).suspended is True

        controller.resume(proc.pid, info.process_key)
        time.sleep(0.3)
        assert controller.current(proc.pid).suspended is False

        # Acting with a mismatched identity (as if the PID were reused) is refused.
        with pytest.raises(ProcessIdentityChangedError):
            controller.terminate(proc.pid, "999999:0")

        controller.terminate(proc.pid, info.process_key)
        assert proc.wait(timeout=5) is not None
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)
