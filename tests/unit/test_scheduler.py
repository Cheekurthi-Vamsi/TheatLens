from __future__ import annotations

import threading
import time

from threatlens.core.models import ComponentHealth, ComponentStatus
from threatlens.core.scheduler import PeriodicTask, Scheduler, TaskRunner
from threatlens.errors import CollectorUnavailableError


class Monotonic:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def make_runner(
    run: object, *, interval: float = 2.0, timeout: float = 10.0, max_backoff: float = 60.0
) -> tuple[TaskRunner, list[tuple[ComponentStatus, ComponentStatus]], Monotonic]:
    transitions: list[tuple[ComponentStatus, ComponentStatus]] = []
    clock = Monotonic()

    def record(old: ComponentHealth, new: ComponentHealth) -> None:
        transitions.append((old.status, new.status))

    runner = TaskRunner(
        PeriodicTask("collector", interval, run, timeout),  # type: ignore[arg-type]
        max_backoff=max_backoff,
        monotonic=clock,
        on_transition=record,
    )
    return runner, transitions, clock


def test_success_marks_ok_and_resets_backoff() -> None:
    runner, transitions, _ = make_runner(lambda: None)
    runner.run_once()
    health = runner.health()
    assert health.status is ComponentStatus.OK and health.runs == 1
    assert runner.next_delay() == 2.0
    assert transitions == [(ComponentStatus.STARTING, ComponentStatus.OK)]


def test_failures_degrade_then_become_unavailable_with_capped_backoff() -> None:
    def fail() -> None:
        raise CollectorUnavailableError("socket tables unavailable")

    runner, transitions, _ = make_runner(fail, interval=2.0, max_backoff=10.0)
    delays = []
    for _ in range(4):
        runner.run_once()
        delays.append(runner.next_delay())
    health = runner.health()
    assert health.status is ComponentStatus.UNAVAILABLE
    assert health.consecutive_failures == 4 and health.failures == 4
    assert health.last_error == "socket tables unavailable"
    assert delays == [4.0, 8.0, 10.0, 10.0]
    assert transitions == [
        (ComponentStatus.STARTING, ComponentStatus.DEGRADED),
        (ComponentStatus.DEGRADED, ComponentStatus.UNAVAILABLE),
    ]


def test_recovery_after_failure() -> None:
    outcomes = iter([RuntimeError("boom"), None])

    def flaky() -> None:
        outcome = next(outcomes)
        if outcome is not None:
            raise outcome

    runner, transitions, _ = make_runner(flaky)
    runner.run_once()
    runner.run_once()
    assert runner.health().status is ComponentStatus.OK
    assert runner.health().last_error == "RuntimeError: boom"  # history retained for status
    assert transitions[-1] == (ComponentStatus.DEGRADED, ComponentStatus.OK)


def test_watchdog_flags_run_exceeding_timeout() -> None:
    clock_holder: dict[str, Monotonic] = {}

    def slow() -> None:
        clock_holder["clock"].now += 30.0
        runner.check_timeout()  # watchdog observes while the run is still in progress

    runner, transitions, clock = make_runner(slow, timeout=5.0)
    clock_holder["clock"] = clock
    runner.run_once()
    assert (ComponentStatus.STARTING, ComponentStatus.TIMED_OUT) in transitions
    assert runner.health().status is ComponentStatus.OK  # the run eventually completed


def test_failing_task_does_not_stop_other_tasks() -> None:
    counter = {"healthy": 0}

    def healthy() -> None:
        counter["healthy"] += 1

    def broken() -> None:
        raise RuntimeError("always fails")

    scheduler = Scheduler(
        [
            TaskRunner(PeriodicTask("broken", 0.01, broken, 5.0), max_backoff=0.02),
            TaskRunner(PeriodicTask("healthy", 0.01, healthy, 5.0)),
        ],
        watchdog_interval=0.05,
    )
    scheduler.start()
    time.sleep(0.3)
    assert scheduler.stop(timeout=2.0) == []
    statuses = {h.name: h.status for h in scheduler.health()}
    assert counter["healthy"] >= 5
    assert statuses == {"broken": ComponentStatus.STOPPED, "healthy": ComponentStatus.STOPPED}


def test_hung_task_is_reported_timed_out_and_as_stuck_on_stop() -> None:
    release = threading.Event()
    scheduler = Scheduler(
        [TaskRunner(PeriodicTask("hung", 0.01, lambda: release.wait(5.0) and None, 0.05))],
        watchdog_interval=0.02,
    )
    scheduler.start()
    time.sleep(0.25)
    assert scheduler.health()[0].status is ComponentStatus.TIMED_OUT
    assert scheduler.stop(timeout=0.1) == ["hung"]
    release.set()
