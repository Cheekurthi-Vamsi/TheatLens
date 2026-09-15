"""A small thread-safe bounded LRU cache.

``functools.lru_cache`` caches by call arguments forever (within its size) and cannot express
"this entry is valid only while the file's size and mtime are unchanged". Hashing and signature
verification need exactly that, keyed on a file fingerprint.
"""

from __future__ import annotations

import threading
from collections import OrderedDict


class BoundedLRUCache[K, V]:
    """Least-recently-used cache with a hard entry limit."""

    def __init__(self, max_entries: int) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be >= 1")
        self._max = max_entries
        self._data: OrderedDict[K, V] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def get(self, key: K) -> V | None:
        with self._lock:
            try:
                self._data.move_to_end(key)
            except KeyError:
                self.misses += 1
                return None
            self.hits += 1
            return self._data[key]

    def put(self, key: K, value: V) -> None:
        with self._lock:
            self._data[key] = value
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._data.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._data)
