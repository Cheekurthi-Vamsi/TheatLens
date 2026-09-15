"""Periodic task scheduling with failure isolation, backoff and a timeout watchdog.

Design
------
* **One thread per task.** A collector that blocks inside a Windows API cannot delay any other
  collector. Python cannot safely kill a thread, so a hung task is not interrupted; instead the
  watchdog marks it ``TIMED_OUT`` (visible in ``status`` and as a ``COLLECTOR_STATUS`` event)
  while everything else keeps running.
* **Fixed delay, not fixed rate.** The next run is scheduled after the previous one finishes, so a
  slow run can never pile up concurrent runs of the same task.
* **Exponential backoff.** After ``n`` consecutive failures the delay becomes
  ``min(max_backoff, interval * 2**n)``; the first success resets it.
* **Status transitions are reported** through a callback so the engine can publish them.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Final

from winsentinel.core.models import ComponentHealth, ComponentStatus
from winsentinel.utils.time import utc_now

logger = logging.getLogger(__name__)

UNAVAILABLE_AFTER_FAILURES: Final = 3

TransitionCallback = Callable[[ComponentHealth, ComponentHealth], None]


@dataclass(frozen=True, slots=True)
class PeriodicTask:
    name: str
    interval: float
    run: Callable[[], None]
    timeout: float


def _describe(exc: BaseException) -> str:
    message = str(exc) or type(exc).__name__
    return (
        message
        if type(exc).__module__.startswith("winsentinel")
        else f"{type(exc).__name__}: {message}"
    )


class TaskRunner:
    """Runs one task and owns its health. Contains no threading, so it is unit-testable."""

    def __init__(
        self,
        task: PeriodicTask,
        *,
        max_backoff: float = 60.0,
        clock: Callable[[], datetime] = utc_now,
        monotonic: Callable[[], float] = time.monotonic,
        on_transition: TransitionCallback | None = None,
    ) -> None:
        self.task = task
        self._max_backoff = max(max_backoff, task.interval)
        self._clock = clock
        self._monotonic = monotonic
        self._on_transition = on_transition
        self._lock = threading.Lock()
        self._running_since: float | None = None
        self._health = ComponentHealth(name=task.name, status=ComponentStatus.STARTING)

    @property
    def name(self) -> str:
        return self.task.name

    def health(self) -> ComponentHealth:
        with self._lock:
            return self._health

    def run_once(self) -> None:
        start = self._monotonic()
        with self._lock:
            self._running_since = start
        try:
            self.task.run()
        except Exception as exc:
            self._record_failure(exc, start)
        else:
            self._record_success(start)
        finally:
            with self._lock:
                self._running_since = None

    def next_delay(self) -> float:
        return self._backoff(self.health().consecutive_failures)

    def _backoff(self, failures: int) -> float:
        if failures == 0:
            return self.task.interval
        return float(min(self._max_backoff, self.task.interval * (2**failures)))

    def check_timeout(self) -> None:
        """Called by the watchdog: flag a run that has exceeded its timeout."""
        with self._lock:
            started = self._running_since
            health = self._health
        if started is None or health.status is ComponentStatus.TIMED_OUT:
            return
        elapsed = self._monotonic() - started
        if elapsed > self.task.timeout:
            self._update(
                status=ComponentStatus.TIMED_OUT,
                detail=f"current run has taken {elapsed:.1f}s (timeout {self.task.timeout:g}s)",
            )
            logger.warning(
                "event=COMPONENT_TIMED_OUT component=%s elapsed=%.1f", self.name, elapsed
            )

    def mark_stopped(self) -> None:
        self._update(status=ComponentStatus.STOPPED, detail=None)

    def _record_success(self, start: float) -> None:
        previous = self.health()
        if previous.consecutive_failures:
            logger.info("event=COMPONENT_RECOVERED component=%s", self.name)
        self._update(
            status=ComponentStatus.OK,
            runs=previous.runs + 1,
            consecutive_failures=0,
            last_success=self._clock(),
            last_duration_ms=round((self._monotonic() - start) * 1000.0, 2),
            detail=None,
        )

    def _record_failure(self, exc: Exception, start: float) -> None:
        previous = self.health()
        consecutive = previous.consecutive_failures + 1
        status = (
            ComponentStatus.DEGRADED
            if consecutive < UNAVAILABLE_AFTER_FAILURES
            else ComponentStatus.UNAVAILABLE
        )
        message = _describe(exc)
        level = logging.WARNING if consecutive == 1 else logging.DEBUG
        logger.log(
            level,
            "event=COMPONENT_FAILED component=%s failures=%s error=%s",
            self.name,
            consecutive,
            message,
        )
        self._update(
            status=status,
            runs=previous.runs + 1,
            failures=previous.failures + 1,
            consecutive_failures=consecutive,
            last_error=message,
            last_error_at=self._clock(),
            last_duration_ms=round((self._monotonic() - start) * 1000.0, 2),
            detail=f"retrying in {self._backoff(consecutive):g}s",
        )

    def _update(self, **changes: object) -> None:
        with self._lock:
            old = self._health
            new = old.model_copy(update=changes)
            self._health = new
        if old.status is not new.status and self._on_transition is not None:
            self._on_transition(old, new)


class Scheduler:
    """Runs each :class:`TaskRunner` on its own thread, plus a watchdog thread."""

    def __init__(self, runners: Sequence[TaskRunner], *, watchdog_interval: float = 1.0) -> None:
        self._runners = tuple(runners)
        self._watchdog_interval = watchdog_interval
        self._stop = threading.Event()
        self._threads: dict[str, threading.Thread] = {}

    @property
    def runners(self) -> tuple[TaskRunner, ...]:
        return self._runners

    def start(self, *, run_immediately: bool = True) -> None:
        """Start one thread per task. With ``run_immediately=False`` each task first waits one
        delay (used when the engine has already performed the first run synchronously)."""
        if self._threads:
            raise RuntimeError("Scheduler already started")
        for runner in self._runners:
            thread = threading.Thread(
                target=self._loop,
                args=(runner, run_immediately),
                name=f"winsentinel-{runner.name}",
                daemon=True,
            )
            self._threads[runner.name] = thread
            thread.start()
        watchdog = threading.Thread(target=self._watchdog, name="winsentinel-watchdog", daemon=True)
        self._threads["watchdog"] = watchdog
        watchdog.start()

    def stop(self, timeout: float) -> list[str]:
        """Signal all threads and wait up to ``timeout``. Returns names of tasks still running."""
        self._stop.set()
        deadline = time.monotonic() + timeout
        stuck: list[str] = []
        for name, thread in self._threads.items():
            thread.join(max(0.0, deadline - time.monotonic()))
            if thread.is_alive() and name != "watchdog":
                stuck.append(name)
        for runner in self._runners:
            if runner.name not in stuck:
                runner.mark_stopped()
        return stuck

    def health(self) -> list[ComponentHealth]:
        return [runner.health() for runner in self._runners]

    def _loop(self, runner: TaskRunner, run_immediately: bool) -> None:
        if not run_immediately and self._stop.wait(runner.next_delay()):
            return
        while not self._stop.is_set():
            runner.run_once()
            if self._stop.wait(runner.next_delay()):
                return

    def _watchdog(self) -> None:
        while not self._stop.wait(self._watchdog_interval):
            for runner in self._runners:
                runner.check_timeout()
