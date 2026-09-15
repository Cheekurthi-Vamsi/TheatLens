"""Benign, self-cleaning test-lab scenarios for WinSentinel.

Nothing here is malicious: harmless stand-ins (a renamed copy of ping.exe, an encoded
Start-Sleep, a loopback socket) exercise the detection rules and clean up after themselves. Run
`winsentinel monitor` in another terminal to watch. See scripts/lab/README.md.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SYSTEM32 = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32"
PING = SYSTEM32 / "PING.EXE"
BASE_PYTHON = getattr(sys, "_base_executable", sys.executable)


def _wait(seconds: float, note: str) -> None:
    print(f"  … {note} (waiting {seconds:g}s)")
    time.sleep(seconds)


def scenario_http_server() -> None:
    print("[1] HTTP server on 127.0.0.1:8000")
    proc = subprocess.Popen(
        [BASE_PYTHON, "-m", "http.server", "8000", "--bind", "127.0.0.1"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(6, "listening on :8000 (expect a LISTENER_OPENED)")
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _run_copy(name: str, note: str) -> None:
    lab = Path(tempfile.gettempdir()) / "winsentinel-lab"
    lab.mkdir(exist_ok=True)
    copy = lab / name
    shutil.copy2(PING, copy)
    proc = subprocess.Popen([str(copy), "-n", "8", "127.0.0.1"], stdout=subprocess.DEVNULL)
    try:
        _wait(6, note)
    finally:
        proc.kill()
        proc.wait(timeout=10)
        with contextlib.suppress(OSError):
            copy.unlink()
        with contextlib.suppress(OSError):
            lab.rmdir()


def scenario_child_exe() -> None:
    print("[2] Benign exe from %TEMP% (expect PROC-001)")
    _run_copy("lab_tool.exe", "running from Temp, pinging 127.0.0.1")


def scenario_masquerade() -> None:
    print("[3] ping.exe renamed svchost.exe in %TEMP% (expect PROC-005 + an alert)")
    _run_copy("svchost.exe", "impersonating a system binary")


def scenario_deceptive() -> None:
    print("[4] ping.exe renamed invoice.pdf.exe (expect PROC-008)")
    _run_copy("invoice.pdf.exe", "double-extension name")


def scenario_encoded_ps() -> None:
    print("[5] PowerShell -EncodedCommand Start-Sleep (expect PROC-006)")
    encoded = base64.b64encode("Start-Sleep -Seconds 5".encode("utf-16-le")).decode()
    proc = subprocess.Popen(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(6, "decoded script should appear in the evidence")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def scenario_chain() -> None:
    print("[6] cmd.exe -> powershell.exe child chain (expect lineage signals)")
    proc = subprocess.Popen(
        ["cmd.exe", "/c", "powershell -NoProfile -Command Start-Sleep -Seconds 5"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        _wait(7, "watch the process tree")
    finally:
        proc.kill()
        proc.wait(timeout=10)


def scenario_drop_file() -> None:
    print("[7] Drop and delete an .exe in %TEMP% (expect FILE_CREATED + FILE-001)")
    dropped = Path(tempfile.gettempdir()) / "winsentinel_lab_dropped.exe"
    shutil.copy2(PING, dropped)
    _wait(4, "file created")
    with contextlib.suppress(OSError):
        dropped.unlink()
    _wait(2, "file deleted")


def scenario_run_key() -> None:
    print("[8] Add and remove a HKCU Run value (expect PERSISTENCE_ADDED + PERSIST-001)")
    if sys.platform != "win32":
        print("  (skipped: Windows only)")
        return
    import winreg

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    name = "WinSentinelLabRunKey"
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, winreg.REG_SZ, r"C:\Windows\System32\calc.exe --lab")
    try:
        _wait(35, "persistence monitor polls every 30s by default")
    finally:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, name)
    print("  removed the test Run value")


SCENARIOS = {
    "http-server": scenario_http_server,
    "child-exe": scenario_child_exe,
    "masquerade": scenario_masquerade,
    "deceptive": scenario_deceptive,
    "encoded-ps": scenario_encoded_ps,
    "chain": scenario_chain,
    "drop-file": scenario_drop_file,
    "run-key": scenario_run_key,
}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true", help="run every scenario in sequence")
    for name in SCENARIOS:
        parser.add_argument(f"--{name}", action="store_true", help=f"run the '{name}' scenario")
    args = parser.parse_args()

    selected = [
        fn for name, fn in SCENARIOS.items() if args.all or getattr(args, name.replace("-", "_"))
    ]
    if not selected:
        parser.print_help()
        return 1
    print("Run 'winsentinel monitor' in another terminal to watch.\n")
    for scenario in selected:
        scenario()
        print()
    print("Lab complete. All artifacts removed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
