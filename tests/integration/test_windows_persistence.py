"""Integration test: the persistence collector sees a real HKCU Run value we add and remove.

Only HKCU (the current user's own hive) is touched, under a clearly-named test value, and it is
always deleted in the finally block. No system state is modified.
"""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.integration

if sys.platform == "win32":
    import winreg

    from winsentinel.collectors.persistence_collector import PersistenceCollector
    from winsentinel.core.models import EventType
    from winsentinel.monitors.persistence_monitor import PersistenceMonitor

_RUN_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
_TEST_VALUE = "WinSentinelIntegrationTest"


def test_new_run_value_is_detected_as_added() -> None:
    monitor = PersistenceMonitor(PersistenceCollector())
    monitor.poll()  # inventory of what already exists
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(
            key, _TEST_VALUE, 0, winreg.REG_SZ, r"C:\Windows\System32\calc.exe --test"
        )
    try:
        events = monitor.poll()
    finally:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, _TEST_VALUE)

    added = [
        e
        for e in events
        if e.event_type is EventType.PERSISTENCE_ADDED and e.data.get("name") == _TEST_VALUE
    ]
    assert added, "the new Run value should be reported as PERSISTENCE_ADDED"
    assert added[0].data["executable"].lower().endswith("calc.exe")
    assert added[0].data["kind"] == "REGISTRY_RUN"

    # And it disappears on the next poll.
    removed = [
        e
        for e in monitor.poll()
        if e.event_type is EventType.PERSISTENCE_REMOVED and e.data.get("name") == _TEST_VALUE
    ]
    assert removed


def test_collector_returns_services_and_run_keys() -> None:
    snapshot = PersistenceCollector().collect()
    kinds = {item.kind.value for item in snapshot.items}
    assert "SERVICE" in kinds  # every Windows box has auto-start services
    assert all(item.item_key for item in snapshot.items)
