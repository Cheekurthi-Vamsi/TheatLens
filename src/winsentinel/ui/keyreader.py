"""Non-blocking keyboard input for the live dashboard.

Windows has no ``select`` on stdin, so we poll ``msvcrt.kbhit`` on a daemon thread and push
decoded keys into a queue the dashboard drains each tick. Navigation keys arrive as a two-character
sequence (0x00 or 0xE0 then a scan code), which we translate to names such as ``UP`` or ``DELETE``.
"""

from __future__ import annotations

import queue
import sys
import threading
from typing import Final

_ARROWS: Final = {
    "H": "UP",
    "P": "DOWN",
    "K": "LEFT",
    "M": "RIGHT",
    "I": "PGUP",
    "Q": "PGDN",
    "G": "HOME",
    "O": "END",
    "S": "DELETE",
}
_PREFIXES: Final = ("\x00", "\xe0")


class KeyReader:
    """Start/stop a background reader. ``get()`` returns the next key or ``None``."""

    def __init__(self) -> None:
        self._queue: queue.Queue[str] = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def available(self) -> bool:
        return sys.platform == "win32" and sys.stdin is not None and sys.stdin.isatty()

    def start(self) -> None:
        if not self.available:
            return
        self._thread = threading.Thread(target=self._run, name="winsentinel-keys", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def get(self) -> str | None:
        try:
            return self._queue.get_nowait()
        except queue.Empty:
            return None

    def _run(self) -> None:
        import msvcrt

        while not self._stop.is_set():
            if not msvcrt.kbhit():
                self._stop.wait(0.05)
                continue
            char = msvcrt.getwch()
            if char in _PREFIXES:
                code = msvcrt.getwch()
                key = _ARROWS.get(code)
                if key:
                    self._queue.put(key)
            elif char in ("\r", "\n"):
                self._queue.put("ENTER")
            else:
                self._queue.put(char)
