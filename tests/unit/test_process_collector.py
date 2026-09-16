from __future__ import annotations

import pytest

from fixtures.fakes import (
    FakeClock,
    FakeDetails,
    FakeInspector,
    FakeSource,
    access_denied,
    entry,
    invalid_parameter,
)
from threatlens.collectors.process_collector import (
    ProcessCollector,
    ProcessCollectorOptions,
    architecture_from_machine,
    cpu_percent,
    integrity_from_rid,
    validate_pid,
)
from threatlens.core.models import Architecture, FieldIssue, IntegrityLevel
from threatlens.errors import CollectorUnavailableError, InvalidInputError, ProcessNotFoundError
from threatlens.security.redaction import REDACTED
from threatlens.utils import windows


def make_collector(
    source: FakeSource,
    inspector: FakeInspector | None = None,
    *,
    clock: FakeClock | None = None,
    cpu_count: int = 4,
    redact: bool = True,
) -> tuple[ProcessCollector, FakeInspector, FakeClock]:
    inspector = inspector or FakeInspector()
    clock = clock or FakeClock()
    collector = ProcessCollector(
        source,
        inspector,
        ProcessCollectorOptions(redact_command_lines=redact),
        clock=clock.now,
        monotonic=clock.monotonic,
        cpu_count=cpu_count,
    )
    return collector, inspector, clock


class TestFieldCollection:
    def test_populates_all_fields_from_bulk_query_and_inspector(self) -> None:
        collector, _, clock = make_collector(FakeSource([entry(100, ppid=50, name="app.exe")]))
        (p,) = collector.collect().processes

        assert (p.pid, p.ppid, p.name) == (100, 50, "app.exe")
        assert p.exe == r"C:\Program Files\App\app.exe"
        assert p.username == r"HOST\alice"
        assert p.integrity_level is IntegrityLevel.MEDIUM
        assert p.architecture is Architecture.X64
        assert p.session_id == 1
        assert p.working_set == 10_000_000
        assert p.suspended is False
        assert p.unavailable == {}
        assert p.collected_at == clock.now()

    def test_command_line_is_redacted_by_default(self) -> None:
        details = FakeDetails(argv=["tool.exe", "--password", "hunter2", "--token=abc"])
        collector, _, _ = make_collector(FakeSource([entry(100)]), FakeInspector({100: details}))
        (p,) = collector.collect().processes
        assert p.cmdline == ("tool.exe", "--password", REDACTED, f"--token={REDACTED}")

    def test_redaction_can_be_disabled(self) -> None:
        details = FakeDetails(argv=["tool.exe", "--password", "hunter2"])
        collector, _, _ = make_collector(
            FakeSource([entry(100)]), FakeInspector({100: details}), redact=False
        )
        (p,) = collector.collect().processes
        assert p.cmdline == ("tool.exe", "--password", "hunter2")

    def test_per_field_access_denied_is_recorded_not_raised(self) -> None:
        details = FakeDetails(
            argv=access_denied(), username=access_denied(), integrity_rid=access_denied()
        )
        collector, _, _ = make_collector(FakeSource([entry(100)]), FakeInspector({100: details}))
        (p,) = collector.collect().processes
        assert p.exe is not None
        assert p.cmdline is None and p.username is None
        assert p.integrity_level is IntegrityLevel.UNKNOWN
        assert p.unavailable == {
            "cmdline": FieldIssue.ACCESS_DENIED,
            "username": FieldIssue.ACCESS_DENIED,
            "integrity_level": FieldIssue.ACCESS_DENIED,
        }

    def test_open_denied_uses_handle_free_image_path_fallback(self) -> None:
        details = FakeDetails(
            open_error=access_denied(), fallback_exe=r"C:\Windows\System32\lsass.exe"
        )
        collector, _, _ = make_collector(
            FakeSource([entry(700, name="lsass.exe")]), FakeInspector({700: details})
        )
        (p,) = collector.collect().processes
        assert p.exe == r"C:\Windows\System32\lsass.exe"
        assert "exe" not in p.unavailable
        assert p.unavailable["cmdline"] is FieldIssue.ACCESS_DENIED
        assert p.unavailable["username"] is FieldIssue.ACCESS_DENIED

    def test_failed_fallback_keeps_access_denied(self) -> None:
        details = FakeDetails(open_error=access_denied(), fallback_exe=access_denied())
        collector, _, _ = make_collector(FakeSource([entry(700)]), FakeInspector({700: details}))
        (p,) = collector.collect().processes
        assert p.exe is None
        assert p.unavailable["exe"] is FieldIssue.ACCESS_DENIED

    def test_pseudo_processes_are_not_applicable_and_have_no_parent(self) -> None:
        source = FakeSource(
            [entry(0, ppid=0, name="System Idle Process"), entry(4, ppid=0, name="System")]
        )
        collector, inspector, _ = make_collector(source)
        idle, system = collector.collect().processes
        assert inspector.open_calls == []
        for p in (idle, system):
            assert p.ppid is None
            assert p.create_time is None
            assert p.unavailable["exe"] is FieldIssue.NOT_APPLICABLE
        assert system.process_key == "4:0"

    def test_bare_image_name_is_not_treated_as_a_path(self) -> None:
        details = FakeDetails(exe="Registry")
        collector, _, _ = make_collector(
            FakeSource([entry(120, name="Registry")]), FakeInspector({120: details})
        )
        (p,) = collector.collect().processes
        assert p.exe is None
        assert p.unavailable["exe"] is FieldIssue.NOT_APPLICABLE

    def test_missing_name_gets_placeholder(self) -> None:
        collector, _, _ = make_collector(FakeSource([entry(900, name="")]))
        assert collector.collect().processes[0].name == "<pid 900>"

    def test_suspended_flag_comes_from_thread_state(self) -> None:
        collector, _, _ = make_collector(FakeSource([entry(100, suspended=True)]))
        assert collector.collect().processes[0].suspended is True


class TestCaching:
    def test_static_fields_read_once_per_process_identity(self) -> None:
        source = FakeSource([entry(100)])
        collector, inspector, clock = make_collector(source)
        for _ in range(3):
            collector.collect()
            clock.advance(2)
        assert inspector.open_calls == [100]

    def test_pid_reuse_triggers_fresh_inspection(self) -> None:
        clock = FakeClock()
        first = entry(100, name="old.exe", created=clock.now().replace(minute=0))
        reused = entry(100, name="new.exe", created=clock.now().replace(minute=4))
        collector, inspector, _ = make_collector(FakeSource([first], [reused]), clock=clock)
        a = collector.collect().processes[0]
        b = collector.collect().processes[0]
        assert a.process_key != b.process_key
        assert inspector.open_calls == [100, 100]

    def test_transient_failures_are_retried(self) -> None:
        details = FakeDetails(open_error=invalid_parameter())
        collector, inspector, _ = make_collector(
            FakeSource([entry(100)]), FakeInspector({100: details})
        )
        (p,) = collector.collect().processes
        assert p.unavailable["cmdline"] is FieldIssue.PROCESS_EXITED
        collector.collect()
        assert inspector.open_calls == [100, 100]

    def test_access_denied_is_cached(self) -> None:
        details = FakeDetails(open_error=access_denied())
        collector, inspector, _ = make_collector(
            FakeSource([entry(100)]), FakeInspector({100: details})
        )
        collector.collect()
        collector.collect()
        assert inspector.open_calls == [100]

    def test_empty_command_line_of_brand_new_process_is_retried(self) -> None:
        clock = FakeClock()
        fresh = entry(100, created=clock.now())  # created "now"
        details = FakeDetails(argv=[])
        collector, inspector, _ = make_collector(
            FakeSource([fresh]), FakeInspector({100: details}), clock=clock
        )
        collector.collect()
        collector.collect()
        assert inspector.open_calls == [100, 100]

    def test_cache_is_pruned_when_process_exits(self) -> None:
        collector, _, _ = make_collector(FakeSource([entry(100), entry(200)], [entry(100)]))
        collector.collect()
        assert collector.cached_process_count == 2
        collector.collect()
        assert collector.cached_process_count == 1


class TestCpu:
    def test_first_sample_is_none_then_normalized_by_cpu_count(self) -> None:
        source = FakeSource([entry(100, cpu_seconds=10.0)], [entry(100, cpu_seconds=11.0)])
        collector, _, clock = make_collector(source, cpu_count=4)
        assert collector.collect().processes[0].cpu_percent is None
        clock.advance(2.0)
        # 1 CPU-second over 2 wall-seconds on 4 logical CPUs = 12.5% of total capacity
        assert collector.collect().processes[0].cpu_percent == 12.5

    @pytest.mark.parametrize(
        ("previous", "cpu_time", "now", "expected"),
        [
            (None, 100, 1.0, None),
            ((100, 1.0), 100, 1.0, None),  # zero elapsed
            ((200, 1.0), 100, 2.0, 0.0),  # counter went backwards (should not happen) -> clamp
            ((0, 0.0), 10 * 10_000_000, 1.0, 100.0),  # 10 cpu-seconds in 1s on 1 cpu -> clamp
        ],
    )
    def test_cpu_percent_edge_cases(
        self, previous: tuple[int, float] | None, cpu_time: int, now: float, expected: float | None
    ) -> None:
        assert cpu_percent(previous, cpu_time, now, 1) == expected


class TestErrors:
    def test_enumeration_failure_raises_collector_unavailable(self) -> None:
        collector, _, _ = make_collector(FakeSource(error=OSError(5, "boom")))
        with pytest.raises(CollectorUnavailableError):
            collector.collect()

    def test_collect_pid_not_found(self) -> None:
        collector, _, _ = make_collector(FakeSource([entry(100)]))
        with pytest.raises(ProcessNotFoundError):
            collector.collect_pid(999)

    def test_collect_pid_inspects_only_the_target(self) -> None:
        collector, inspector, _ = make_collector(FakeSource([entry(100), entry(200), entry(300)]))
        assert collector.collect_pid(200).pid == 200
        assert inspector.open_calls == [200]

    @pytest.mark.parametrize("bad", [-1, 2**32, True, "12", 1.5])
    def test_validate_pid_rejects_invalid(self, bad: object) -> None:
        with pytest.raises(InvalidInputError):
            validate_pid(bad)


@pytest.mark.parametrize(
    ("rid", "level"),
    [
        (0x0000, IntegrityLevel.UNTRUSTED),
        (0x1000, IntegrityLevel.LOW),
        (0x2000, IntegrityLevel.MEDIUM),
        (0x2100, IntegrityLevel.MEDIUM),  # MediumPlus (UIAccess)
        (0x3000, IntegrityLevel.HIGH),
        (0x4000, IntegrityLevel.SYSTEM),
        (-1, IntegrityLevel.UNKNOWN),
    ],
)
def test_integrity_from_rid(rid: int, level: IntegrityLevel) -> None:
    assert integrity_from_rid(rid) is level


@pytest.mark.parametrize(
    ("process_machine", "native", "expected"),
    [
        (windows.IMAGE_FILE_MACHINE_UNKNOWN, windows.IMAGE_FILE_MACHINE_AMD64, Architecture.X64),
        (windows.IMAGE_FILE_MACHINE_I386, windows.IMAGE_FILE_MACHINE_AMD64, Architecture.X86),
        (windows.IMAGE_FILE_MACHINE_UNKNOWN, windows.IMAGE_FILE_MACHINE_ARM64, Architecture.ARM64),
        (0x1234, windows.IMAGE_FILE_MACHINE_AMD64, Architecture.UNKNOWN),
    ],
)
def test_architecture_from_machine(
    process_machine: int, native: int, expected: Architecture
) -> None:
    assert architecture_from_machine(windows.MachineInfo(process_machine, native)) is expected
