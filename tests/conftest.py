from __future__ import annotations

import sys

import pytest

from threatlens.security.privileges import detect_privileges


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    not_windows = sys.platform != "win32"
    elevated = (not not_windows) and detect_privileges().elevated
    for item in items:
        if not_windows and item.get_closest_marker("integration"):
            item.add_marker(pytest.mark.skip(reason="integration tests require Windows"))
        if item.get_closest_marker("requires_admin") and not elevated:
            item.add_marker(pytest.mark.skip(reason="requires an elevated token"))
