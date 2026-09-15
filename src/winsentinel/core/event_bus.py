"""Bounded publish/subscribe event bus with a single dispatcher thread.

Design
------
* **Bounded.** The queue holds at most ``capacity`` events. When full, the *oldest* event is
  dropped and counted: under an event storm the newest information is usually the most useful,
  memory stays bounded, and the drop counter surfaces in ``winsentinel status`` so loss is never
  silent.
* **One dispatcher thread.** Handlers (state history, detection, printing, later storage) run
  sequentially on one thread, so they never race each other and need no locking between them.
* **Exception isolation.** A failing handler is logged and counted; other handlers still receive
  the event and the dispatcher keeps running.
* **Graceful drain.** ``stop()`` refuses new events, then dispatches what is queued until the
  deadline.
"""

from __future__ import annotations

import logging
import threading
import time
from collections import deque
from collections.abc import Callable, Collection
from dataclasses import dataclass
from typing import Final

from winsentinel.core.models import BusStats, EventType, SecurityEvent

logger = logging.getLogger(__name__)

# Return values are ignored, so handlers that also return something (e.g. detection results) fit.
Handler = Callable[[SecurityEvent], object]

_WAIT_SECONDS: Final = 0.25
_LATENCY_SMOOTHING: Final = 0.1  # EWMA weight of the newest sample


@dataclass(slots=True)
class _Subscription:
    name: str
    handler: Handler
    event_types: frozenset[EventType] | None
    errors: int = 0


class EventBus:
    """Thread-safe bounded event bus."""

    def __init__(
        self, capacity: int = 10_000, *, monotonic: Callable[[], float] = time.monotonic
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self._capacity = capacity
        self._monotonic = monotonic
        self._queue: deque[tuple[SecurityEvent, float]] = deque()
        self._condition = threading.Condition()
        self._subscriptions: tuple[_Subscription, ...] = ()
        self._accepting = True
        self._stopping = False
        self._thread: threading.Thread | None = None
        self._published = 0
        self._dispatched = 0
        self._dropped = 0
        self._handler_errors = 0
        self._latency_ms: float | None = None

    # -- subscription -----------------------------------------------------------------------

    def subscribe(
        self, name: str, handler: Handler, event_types: Collection[EventType] | None = None
    ) -> None:
        """Register ``handler`` for ``event_types`` (all types when ``None``)."""
        subscription = _Subscription(
            name, handler, None if event_types is None else frozenset(event_types)
        )
        with self._condition:
            # Copy-on-write so the dispatcher can iterate without holding the lock.
            self._subscriptions = (*self._subscriptions, subscription)

    # -- publishing -------------------------------------------------------------------------

    def publish(self, event: SecurityEvent) -> bool:
        """Enqueue ``event``. Returns ``False`` only when the bus is no longer accepting events."""
        with self._condition:
            if not self._accepting:
                self._dropped += 1
                return False
            if len(self._queue) >= self._capacity:
                self._queue.popleft()
                self._dropped += 1
            self._queue.append((event, self._monotonic()))
            self._published += 1
            self._condition.notify()
            return True

    # -- dispatching ------------------------------------------------------------------------

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("EventBus already started")
        # daemon=True: a handler stuck in a system call must not keep the process alive forever;
        # orderly shutdown still drains and joins via stop().
        self._thread = threading.Thread(
            target=self._run, name="winsentinel-dispatcher", daemon=True
        )
        self._thread.start()

    def dispatch_pending(self, max_events: int | None = None) -> int:
        """Synchronously dispatch queued events on the calling thread (tests, single-shot use)."""
        count = 0
        while max_events is None or count < max_events:
            with self._condition:
                if not self._queue:
                    return count
                event, enqueued = self._queue.popleft()
            self._dispatch(event, enqueued)
            count += 1
        return count

    def stop(self, timeout: float) -> bool:
        """Stop accepting events, drain the queue, and join the dispatcher.

        Returns ``True`` if every queued event was dispatched before ``timeout``.
        """
        with self._condition:
            self._accepting = False
            self._stopping = True
            self._condition.notify_all()
        if self._thread is None:
            self.dispatch_pending()
        else:
            self._thread.join(timeout)
        with self._condition:
            return not self._queue

    def _run(self) -> None:
        while True:
            with self._condition:
                while not self._queue and not self._stopping:
                    self._condition.wait(_WAIT_SECONDS)
                if not self._queue:
                    return  # stopping and drained
                event, enqueued = self._queue.popleft()
            self._dispatch(event, enqueued)

    def _dispatch(self, event: SecurityEvent, enqueued: float) -> None:
        latency_ms = (self._monotonic() - enqueued) * 1000.0
        for subscription in self._subscriptions:
            if (
                subscription.event_types is not None
                and event.event_type not in subscription.event_types
            ):
                continue
            try:
                subscription.handler(event)
            except Exception as exc:
                subscription.errors += 1
                with self._condition:
                    self._handler_errors += 1
                # First failure per handler at WARNING, the rest at DEBUG to avoid log floods.
                level = logging.WARNING if subscription.errors == 1 else logging.DEBUG
                logger.log(
                    level,
                    "event=HANDLER_FAILED handler=%s event_type=%s error=%s",
                    subscription.name,
                    event.event_type.value,
                    exc,
                    exc_info=logger.isEnabledFor(logging.DEBUG),
                )
        with self._condition:
            self._dispatched += 1
            previous = self._latency_ms
            self._latency_ms = (
                latency_ms
                if previous is None
                else previous + _LATENCY_SMOOTHING * (latency_ms - previous)
            )

    # -- observability ----------------------------------------------------------------------

    def stats(self) -> BusStats:
        with self._condition:
            return BusStats(
                capacity=self._capacity,
                queued=len(self._queue),
                published=self._published,
                dispatched=self._dispatched,
                dropped=self._dropped,
                handler_errors=self._handler_errors,
                avg_latency_ms=None if self._latency_ms is None else round(self._latency_ms, 3),
            )
