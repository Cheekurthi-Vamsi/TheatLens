"""Command-line interface and composition root.

This is the only module that knows how the object graph is wired (config → collectors →
views). Everything else receives its dependencies, which keeps it testable.

Phase 1 commands: ``processes``, ``process``, ``tree``, ``config``. Later phases register their
commands here as they are implemented — commands are never registered before they work.
"""

from __future__ import annotations

import argparse
import contextlib
import logging
import os
import sys
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final

from rich.console import Console, Group, RenderableType
from rich.json import JSON
from rich.text import Text

from winsentinel import __version__
from winsentinel.collectors.network_collector import NetworkCollector
from winsentinel.collectors.persistence_collector import PersistenceCollector
from winsentinel.collectors.process_collector import (
    ProcessCollector,
    ProcessCollectorOptions,
    ProcessEnricher,
    validate_pid,
)
from winsentinel.config import (
    Config,
    app_data_dir,
    default_config_path,
    load_config,
    write_default_config,
)
from winsentinel.core.diagnostics import process_instance_alive, run_self_test
from winsentinel.core.engine import Engine
from winsentinel.core.models import (
    ActionOutcome,
    ActionType,
    AddressScope,
    ConnectionState,
    CorrelatedConnection,
    FieldIssue,
    ProcessInfo,
    ProcessNode,
    ProcessSnapshot,
    ResponseAction,
)
from winsentinel.core.status_file import (
    LOCK_FILE_NAME,
    InstanceLock,
    StatusFile,
    default_status_path,
    is_status_current,
)
from winsentinel.correlation.process_network import (
    ACTIVE_EXCLUDED_STATES,
    connection_chain,
    correlate,
    group_by_process,
    lookup_from_processes,
)
from winsentinel.correlation.process_tree import (
    ancestry,
    build_process_tree,
    children_of,
    find_node,
)
from winsentinel.detection.alerting import AlertManager, build_alert
from winsentinel.detection.allowlist import AllowlistMatcher, AllowlistMatchType, entry_from_row
from winsentinel.detection.baseline import (
    BaselineItem,
    BaselineItemKind,
    capture_baseline,
    compare_baseline,
    diffs_by_kind,
)
from winsentinel.detection.engine import DetectionEngine, own_process_keys
from winsentinel.detection.rules import build_rules, rule_catalog
from winsentinel.detection.scan import scan_process
from winsentinel.detection.scoring import score_detections
from winsentinel.detection.settings import DetectionSettings
from winsentinel.errors import ExitCode, InvalidInputError, ProcessNotFoundError, WinSentinelError
from winsentinel.logging_config import configure_logging
from winsentinel.response.firewall_control import (
    FirewallController,
    FirewallRuleSpec,
    block_ip_spec,
    block_port_spec,
    block_program_spec,
)
from winsentinel.response.process_control import ProcessController
from winsentinel.response.protection import ProtectionPolicy
from winsentinel.response.response_manager import ResponseManager, current_user
from winsentinel.security.hashing import FileHasher
from winsentinel.security.privileges import ELEVATION_HINT, PrivilegeState, detect_privileges
from winsentinel.security.signatures import SignatureVerifier
from winsentinel.storage.database import Database, loads
from winsentinel.storage.repositories import DatabaseInfo, SecurityStore, alert_from_row
from winsentinel.storage.writer import DatabaseWriter
from winsentinel.ui import colors
from winsentinel.ui.alert_views import alert_detail, alerts_table, breakdown_text
from winsentinel.ui.baseline_views import (
    allowlist_table,
    baseline_compare_view,
    baselines_table,
)
from winsentinel.ui.dashboard import Dashboard
from winsentinel.ui.detection_views import detections_section, rule_detail, rules_table
from winsentinel.ui.event_stream import ALL_CATEGORIES, DEFAULT_CATEGORIES, EventStreamPrinter
from winsentinel.ui.formatting import sanitize_display
from winsentinel.ui.json_output import connection_record, envelope, json_line, write_json
from winsentinel.ui.network_views import (
    connection_chain_text,
    connections_table,
    process_connections_tree,
    process_network_table,
)
from winsentinel.ui.process_views import (
    describe_unverified_parent,
    process_detail,
    process_table,
    process_tree,
)
from winsentinel.ui.response_views import action_result_text, action_warning
from winsentinel.ui.status_view import status_view
from winsentinel.ui.storage_views import (
    db_info_view,
    event_row_json,
    events_table,
    persistence_table,
)
from winsentinel.utils.time import parse_duration, utc_now
from winsentinel.utils.windows import get_windows_version

logger = logging.getLogger("winsentinel.cli")

EXIT_INTERRUPTED: Final = 130
DEFAULT_CPU_SAMPLE_SECONDS: Final = 0.5
MAX_CPU_SAMPLE_SECONDS: Final = 10.0
BYTES_PER_MB: Final = 1024 * 1024

IDLE_PID: Final = 0

SORT_KEYS: Final[dict[str, Callable[[ProcessInfo], tuple[float | str | int, ...]]]] = {
    # The Idle process's "CPU" is unused capacity, not work; keep it out of the top of the list.
    "cpu": lambda p: (p.pid == IDLE_PID, -(p.cpu_percent or 0.0), p.name.lower(), p.pid),
    "memory": lambda p: (-(p.working_set or 0), p.name.lower(), p.pid),
    "pid": lambda p: (p.pid,),
    "name": lambda p: (p.name.lower(), p.pid),
}


# --------------------------------------------------------------------------------------------
# Argument types (validation of untrusted input happens here, at the boundary)
# --------------------------------------------------------------------------------------------


def _pid_arg(value: str) -> int:
    try:
        return validate_pid(int(value, 10))
    except (ValueError, InvalidInputError):
        raise argparse.ArgumentTypeError(
            f"invalid PID {value!r}: expected a non-negative integer"
        ) from None


def _bounded_float(low: float, high: float) -> Callable[[str], float]:
    def parse(value: str) -> float:
        try:
            number = float(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{value!r} is not a number") from None
        if not low <= number <= high:
            raise argparse.ArgumentTypeError(f"must be between {low} and {high}")
        return number

    return parse


def _positive_int(value: str) -> int:
    try:
        number = int(value, 10)
    except ValueError:
        raise argparse.ArgumentTypeError(f"{value!r} is not an integer") from None
    if number < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return number


# --------------------------------------------------------------------------------------------
# Context
# --------------------------------------------------------------------------------------------


@dataclass(slots=True)
class AppContext:
    args: argparse.Namespace
    config: Config
    config_path: Path
    config_loaded: bool
    console: Console
    err_console: Console
    privileges: PrivilegeState

    @property
    def json(self) -> bool:
        return bool(self.args.json)

    @property
    def quiet(self) -> bool:
        return bool(self.args.quiet)

    def collector(self) -> ProcessCollector:
        return ProcessCollector(
            options=ProcessCollectorOptions(
                redact_command_lines=self.config.process.redact_command_lines
            )
        )

    def network_collector(self) -> NetworkCollector:
        return NetworkCollector()

    def detection_settings(self) -> DetectionSettings:
        return DetectionSettings.from_config(self.config)

    def database_path(self) -> Path:
        return self.config.general.resolved_database_path()

    def open_store(self, *, read_only: bool = False) -> SecurityStore:
        """Open the security database. Read commands should use ``read_only=True``."""
        path = self.database_path()
        if read_only and not path.exists():
            raise WinSentinelError(
                f"No database at {path}. Run 'winsentinel monitor' to record activity first."
            )
        db = Database(path, read_only=read_only) if read_only else Database.open(path)
        return SecurityStore(db)

    def enricher(self) -> ProcessEnricher:
        return ProcessEnricher(
            FileHasher(max_file_size=self.config.process.hash_max_file_size_mb * BYTES_PER_MB),
            SignatureVerifier(),
            verify_signatures=self.config.process.verify_signatures,
        )

    def sampled_snapshot(self, seconds: float) -> ProcessSnapshot:
        """Two snapshots ``seconds`` apart so CPU usage is populated."""
        collector = self.collector()
        snapshot = collector.collect()
        if seconds > 0:
            time.sleep(seconds)
            snapshot = collector.collect()
        return snapshot

    def privilege_hint(self, processes: Sequence[ProcessInfo]) -> None:
        if self.json or self.quiet or self.privileges.elevated:
            return
        if any(FieldIssue.ACCESS_DENIED in p.unavailable.values() for p in processes):
            self.err_console.print(Text(ELEVATION_HINT, style=colors.MUTED))


# --------------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------------


def cmd_processes(ctx: AppContext) -> int:
    args = ctx.args
    snapshot = ctx.sampled_snapshot(args.sample)
    processes = list(snapshot.processes)
    if args.name:
        needle = args.name.lower()
        processes = [p for p in processes if needle in p.name.lower()]
    if args.user:
        needle = args.user.lower()
        processes = [p for p in processes if p.username and needle in p.username.lower()]
    processes.sort(key=SORT_KEYS[args.sort])
    if args.limit:
        processes = processes[: args.limit]
    if args.verify:
        enricher = ctx.enricher()
        if ctx.json or ctx.quiet:
            processes = [enricher.enrich(p) for p in processes]
        else:
            with ctx.err_console.status(
                "Hashing and verifying signatures (cached after first run)…"
            ):
                processes = [enricher.enrich(p) for p in processes]

    if ctx.json:
        write_json(
            envelope(
                "processes",
                elevated=ctx.privileges.elevated,
                total=len(snapshot.processes),
                processes=processes,
            ),
            sys.stdout,
        )
        return ExitCode.OK

    ctx.console.print(process_table(processes, show_signature=args.verify))
    if not ctx.quiet:
        ctx.console.print(
            Text(
                f"{len(processes)} of {len(snapshot.processes)} processes · CPU sampled over "
                f"{args.sample:g}s · {'elevated' if ctx.privileges.elevated else 'standard user'}",
                style=colors.MUTED,
            )
        )
    ctx.privilege_hint(processes)
    return ExitCode.OK


def cmd_process(ctx: AppContext) -> int:
    pid: int = ctx.args.pid
    snapshot = ctx.sampled_snapshot(ctx.args.sample)
    by_pid = snapshot.by_pid()
    process = by_pid.get(pid)
    if process is None:
        raise ProcessNotFoundError(pid)
    if not ctx.args.no_verify:
        process = ctx.enricher().enrich(process)
    parents = ancestry(process, by_pid)
    children = children_of(process, snapshot.processes)

    if ctx.json:
        write_json(
            envelope(
                "process",
                elevated=ctx.privileges.elevated,
                process=process,
                ancestry=[_process_ref(p) for p in parents],
                children=[_process_ref(p) for p in children],
            ),
            sys.stdout,
        )
        return ExitCode.OK

    ctx.console.print(
        process_detail(
            process, parents, children, parent_note=describe_unverified_parent(process, by_pid)
        )
    )
    ctx.privilege_hint([process])
    return ExitCode.OK


def _network_view(ctx: AppContext) -> tuple[ProcessSnapshot, list[CorrelatedConnection]]:
    """Processes first, then sockets, so every socket's owner is already known when joined."""
    processes = ctx.collector().collect()
    sockets = ctx.network_collector().collect()
    if sockets.unavailable_tables and not ctx.quiet and not ctx.json:
        ctx.err_console.print(
            Text(
                "warning: socket tables unavailable: " + ", ".join(sockets.unavailable_tables),
                style=colors.WARNING,
            )
        )
    lookup = lookup_from_processes(processes.processes)
    return processes, correlate(sockets.connections, lookup)


def _matches_filters(item: CorrelatedConnection, args: argparse.Namespace) -> bool:
    c = item.connection
    if args.protocol and c.protocol.value != args.protocol.upper():
        return False
    if args.pid is not None and c.pid != args.pid:
        return False
    if getattr(args, "state", None) and c.state.value != args.state:
        return False
    if args.external and c.remote_scope is not AddressScope.PUBLIC:
        return False
    return not (getattr(args, "listening", False) and not c.is_listener)


def _network_sort_key(item: CorrelatedConnection) -> tuple[str, str, int, int]:
    c = item.connection
    return ((item.process_name or "~").lower(), c.protocol.value, c.local_port, c.pid)


def cmd_network(ctx: AppContext) -> int:
    snapshot, correlated = _network_view(ctx)
    items = sorted((i for i in correlated if _matches_filters(i, ctx.args)), key=_network_sort_key)
    if ctx.json:
        write_json(
            envelope(
                "network",
                elevated=ctx.privileges.elevated,
                total=len(correlated),
                connections=[connection_record(i) for i in items],
            ),
            sys.stdout,
        )
        return ExitCode.OK
    ctx.console.print(connections_table(items))
    if not ctx.quiet:
        external = sum(1 for i in items if i.connection.remote_scope is AddressScope.PUBLIC)
        listeners = sum(1 for i in items if i.connection.is_listener)
        ctx.console.print(
            Text(
                f"{len(items)} of {len(correlated)} sockets · {listeners} listening/bound · "
                f"{external} external · {len(snapshot.processes)} processes",
                style=colors.MUTED,
            )
        )
    return ExitCode.OK


def cmd_connections(ctx: AppContext) -> int:
    snapshot, correlated = _network_view(ctx)
    items = [
        i
        for i in correlated
        if i.connection.state not in ACTIVE_EXCLUDED_STATES and _matches_filters(i, ctx.args)
    ]
    processes_by_key = snapshot.by_key()
    if ctx.args.verify:
        enricher = ctx.enricher()
        owner_keys = {i.process_key for i in items if i.process_key}
        for key in owner_keys:
            processes_by_key[key] = enricher.enrich(processes_by_key[key])
    groups = group_by_process(items, processes_by_key)

    if ctx.json:
        write_json(
            envelope(
                "connections",
                elevated=ctx.privileges.elevated,
                processes=[
                    {
                        "pid": g.pid,
                        "attribution": g.attribution.value,
                        "process": g.process,
                        "connections": [connection_record(i) for i in g.connections],
                    }
                    for g in groups
                ],
            ),
            sys.stdout,
        )
        return ExitCode.OK

    title = f"{len(items)} active connections across {len(groups)} processes"
    ctx.console.print(process_connections_tree(groups, title=title, show_signature=ctx.args.verify))
    return ExitCode.OK


def cmd_inspect(ctx: AppContext) -> int:
    pid: int = ctx.args.pid
    snapshot = ctx.sampled_snapshot(ctx.args.sample)
    process = snapshot.by_pid().get(pid)
    if process is None:
        raise ProcessNotFoundError(pid)
    process = ctx.enricher().enrich(process)
    processes = [process if p.process_key == process.process_key else p for p in snapshot.processes]
    by_pid = {p.pid: p for p in processes}
    parents = ancestry(process, by_pid)
    children = children_of(process, processes)

    sockets = ctx.network_collector().collect()
    correlated = correlate(sockets.connections, lookup_from_processes(processes))
    owned = sorted(
        (i for i in correlated if i.process_key == process.process_key),
        key=lambda i: (
            i.connection.is_listener,
            i.connection.protocol.value,
            i.connection.local_port,
        ),
    )
    external_chains = [
        connection_chain(i, processes)
        for i in owned
        if i.connection.remote_scope is AddressScope.PUBLIC
    ]
    detections = scan_process(
        process, processes, correlated, ctx.detection_settings(), now=utc_now()
    )
    risk = score_detections(detections)
    alert = build_alert(process.process_key, detections, running=True) if detections else None

    if ctx.json:
        write_json(
            envelope(
                "inspect",
                elevated=ctx.privileges.elevated,
                process=process,
                ancestry=[_process_ref(p) for p in parents],
                children=[_process_ref(p) for p in children],
                connections=[connection_record(i) for i in owned],
                detections=detections,
                risk={
                    "score": risk.score,
                    "severity": risk.severity.value,
                    "confidence": risk.confidence.value,
                },
                alert=alert
                if alert and alert.risk_score >= ctx.config.detection.alert_threshold
                else None,
            ),
            sys.stdout,
        )
        return ExitCode.OK

    network_section: RenderableType = (
        process_network_table(owned)
        if owned
        else Text("no sockets owned by this process", style=colors.MUTED)
    )
    extra: list[tuple[str, RenderableType]] = [("NETWORK", network_section)]
    if external_chains:
        extra.append(
            (
                "EXTERNAL COMMUNICATION CHAINS",
                Group(*(connection_chain_text(c) for c in external_chains)),
            )
        )
    catalog = {meta.rule_id: meta for meta in rule_catalog()}
    if detections:
        summary = Text()
        summary.append(f"{risk.score}/100 ", style=f"bold {colors.SEVERITY_STYLES[risk.severity]}")
        summary.append(risk.severity.value, style=colors.SEVERITY_STYLES[risk.severity])
        summary.append(
            f"  ({risk.confidence.value} confidence, {len(risk.contributions)} indicators)"
        )
        summary.append("\n")
        summary.append_text(breakdown_text(risk.contributions))
        extra.append(("COMBINED RISK", summary))
    extra.append((f"DETECTIONS ({len(detections)})", detections_section(detections, catalog)))
    ctx.console.print(
        process_detail(
            process,
            parents,
            children,
            parent_note=describe_unverified_parent(process, by_pid),
            extra_sections=extra,
            title="PROCESS INSPECTION",
        )
    )
    ctx.privilege_hint([process])
    return ExitCode.OK


def _parse_categories(value: str | None) -> frozenset[str]:
    if not value:
        return DEFAULT_CATEGORIES
    requested = {part.strip().lower() for part in value.split(",") if part.strip()}
    if "all" in requested:
        return frozenset(ALL_CATEGORIES)
    unknown = requested - set(ALL_CATEGORIES)
    if unknown:
        raise InvalidInputError(
            f"Unknown event categories: {', '.join(sorted(unknown))}. "
            f"Choose from: {', '.join(ALL_CATEGORIES)}, all"
        )
    return frozenset(requested)


def _load_allowlist(ctx: AppContext) -> AllowlistMatcher | None:
    """Load allowlist entries from the database, if one exists."""
    path = ctx.database_path()
    if not path.exists():
        return None
    try:
        store = ctx.open_store(read_only=True)
        try:
            entries = [entry_from_row(row) for row in store.allowlist_entries()]
        finally:
            store.db.close()
    except (OSError, WinSentinelError):
        return None
    return AllowlistMatcher(entries) if entries else None


def _use_dashboard(ctx: AppContext, args: argparse.Namespace) -> bool:
    """Default view is the live dashboard on an interactive terminal; the line stream otherwise."""
    if ctx.json or args.stream:
        return False
    if args.dashboard:  # explicitly requested
        return True
    return ctx.console.is_terminal and not ctx.quiet


def cmd_monitor(ctx: AppContext) -> int:
    args = ctx.args
    categories = _parse_categories(args.events)
    human = not ctx.json and not ctx.quiet
    with InstanceLock(app_data_dir() / LOCK_FILE_NAME):
        writer: DatabaseWriter | None = None
        if not args.no_store:
            _prepare_database(ctx)
            writer = DatabaseWriter(ctx.database_path())
        engine = Engine(
            ctx.config,
            process_collector=ctx.collector(),
            network_collector=ctx.network_collector(),
            attribution_collector=ctx.collector(),
            enricher=ctx.enricher(),
            status_file=StatusFile(default_status_path()),
            writer=writer,
            interval=args.interval,
        )
        settings = ctx.detection_settings()
        detection = DetectionEngine(
            build_rules(settings),
            engine.state,
            disabled_rules=settings.disabled_rules,
            ignored_executables=settings.ignored_executables,
        )
        # Exclusion must exist before the engine starts: inventory is evaluated immediately.
        detection.exclude_process_keys(
            own_process_keys(ctx.collector().collect().processes, os.getpid())
        )
        detection.set_allowlist(_load_allowlist(ctx))
        alerts = AlertManager(
            ctx.config.detection.alert_threshold, running_check=engine.state.is_running
        )
        detection.subscribe(alerts.handle)
        if writer is not None:
            detection.subscribe(writer.on_detection)
            alerts.subscribe(writer.on_alert)
        engine.set_detection_stats(
            rules_enabled=len(detection.enabled_rules),
            detection_count=lambda: detection.stats().detections,
        )

        use_dashboard = _use_dashboard(ctx, args)
        printer: EventStreamPrinter | None = None
        dashboard: Dashboard | None = None
        if use_dashboard:
            dashboard = Dashboard(
                ctx.console,
                engine,
                detection,
                alerts,
                elevated=ctx.privileges.elevated,
                refresh=engine.interval,
            )
            engine.subscribe("dashboard", dashboard.on_event)
        else:
            printer = EventStreamPrinter(
                ctx.console, categories=categories, show_loopback=args.loopback, json_lines=ctx.json
            )
            engine.subscribe("stream", printer.on_event, printer.event_types)
            detection.subscribe(printer.on_detection)
            alerts.subscribe(printer.on_alert)
        # Detection is subscribed after the stream so each event line prints before any detection.
        engine.subscribe("detection", detection.handle, detection.event_types)

        if printer is not None and human:
            ctx.err_console.print(
                Text(
                    f"WinSentinel monitor · every {engine.interval:g}s · "
                    f"{'elevated' if ctx.privileges.elevated else 'standard user'} · "
                    f"showing {', '.join(sorted(categories))} · Ctrl+C to stop",
                    style=colors.MUTED,
                )
            )
        deadline = None if args.duration is None else time.monotonic() + args.duration
        try:
            engine.start()
            if dashboard is not None:
                dashboard.run(duration=args.duration)
            else:
                if printer is not None and human:
                    counts = engine.state.counts()
                    ctx.err_console.print(
                        Text(
                            f"Watching {counts.processes} processes and "
                            f"{counts.connections} sockets (already-running items are inventory).",
                            style=colors.MUTED,
                        )
                    )
                while deadline is None or time.monotonic() < deadline:
                    time.sleep(0.25)
        except KeyboardInterrupt:
            pass
        finally:
            report = engine.stop()
        detection_stats = detection.stats()

    if ctx.json:
        sys.stdout.write(
            json_line(
                {
                    "kind": "shutdown",
                    "duration_seconds": report.duration_seconds,
                    "events_published": report.events_published,
                    "events_dropped": report.events_dropped,
                    "drained": report.drained,
                    "stuck_components": list(report.stuck_components),
                    "detections": detection_stats.detections,
                    "alerts": alerts.raised,
                    "rule_errors": detection_stats.rule_errors,
                }
            )
            + "\n"
        )
    elif not ctx.quiet:
        stuck = (
            f" · still running: {', '.join(report.stuck_components)}"
            if report.stuck_components
            else ""
        )
        ctx.err_console.print(
            Text(
                f"Stopped after {report.duration_seconds:.1f}s · {report.events_dispatched} events "
                f"processed · {detection_stats.detections} detections · {alerts.raised} alerts · "
                f"{report.events_dropped} dropped · "
                f"{'clean shutdown' if report.drained else 'queue not fully drained'}{stuck}",
                style=colors.MUTED,
            )
        )
    return ExitCode.OK


def cmd_status(ctx: AppContext) -> int:
    now = utc_now()
    engine_status = StatusFile(default_status_path()).read()
    live = False
    if engine_status is not None:
        alive = process_instance_alive(
            ctx.collector(), engine_status.pid, engine_status.process_key
        )
        stale_after = timedelta(seconds=max(10.0, 5 * ctx.config.engine.status_interval_seconds))
        live = is_status_current(engine_status, now, stale_after=stale_after, process_alive=alive)

    checks = (
        []
        if ctx.args.no_self_test
        else run_self_test(ctx.collector(), ctx.network_collector(), SignatureVerifier())
    )
    try:
        version = get_windows_version()
        windows_text = f"{version.product} {version.edition} (build {version.build})"
    except WinSentinelError:
        windows_text = "unknown"
    privileges = "administrator (elevated)" if ctx.privileges.elevated else "standard user"
    system_rows = [
        ("WinSentinel", __version__),
        ("Windows", windows_text),
        ("Privileges", privileges),
        ("Config", f"{ctx.config_path} ({'loaded' if ctx.config_loaded else 'defaults'})"),
    ]

    if ctx.json:
        write_json(
            envelope(
                "status",
                engine_running=live,
                engine=engine_status,
                windows=windows_text,
                elevated=ctx.privileges.elevated,
                config_path=str(ctx.config_path),
                self_test=[
                    {"name": c.name, "ok": c.ok, "duration_ms": c.duration_ms, "detail": c.detail}
                    for c in checks
                ],
            ),
            sys.stdout,
        )
    else:
        ctx.console.print(
            status_view(
                now=now,
                engine=engine_status,
                engine_live=live,
                system_rows=system_rows,
                checks=checks,
            )
        )
    return ExitCode.OK if all(c.ok for c in checks) else ExitCode.ERROR


def cmd_rules(ctx: AppContext) -> int:
    catalog = rule_catalog()
    disabled = set(ctx.config.detection.disabled_rules)
    rule_id = getattr(ctx.args, "rule_id", None)
    if rule_id is not None:
        wanted = rule_id.upper()
        meta = next((m for m in catalog if m.rule_id == wanted), None)
        if meta is None:
            raise InvalidInputError(
                f"Unknown rule {rule_id!r}. Run 'winsentinel rules' to list available rules."
            )
        enabled = meta.rule_id not in disabled and meta.enabled_by_default
        if ctx.json:
            write_json(envelope("rule", enabled=enabled, rule=meta), sys.stdout)
        else:
            ctx.console.print(rule_detail(meta, enabled=enabled))
        return ExitCode.OK

    if ctx.json:
        write_json(
            envelope(
                "rules",
                rules=[
                    {
                        **m.model_dump(mode="json"),
                        "enabled": m.rule_id not in disabled and m.enabled_by_default,
                    }
                    for m in catalog
                ],
            ),
            sys.stdout,
        )
        return ExitCode.OK
    ctx.console.print(rules_table(catalog, disabled))
    if not ctx.quiet:
        ctx.console.print(
            Text(
                f"{len(catalog)} rules · scores are per-rule contributions (max +60), not risk "
                "verdicts · 'winsentinel rules show <RULE_ID>' for details",
                style=colors.MUTED,
            )
        )
    return ExitCode.OK


def _process_ref(process: ProcessInfo) -> dict[str, object]:
    return {"pid": process.pid, "name": process.name, "process_key": process.process_key}


def _node_to_dict(node: ProcessNode) -> dict[str, object]:
    p = node.process
    return {
        "pid": p.pid,
        "ppid": p.ppid,
        "name": p.name,
        "process_key": p.process_key,
        "exe": p.exe,
        "username": p.username,
        "parent_verified": node.parent_verified,
        "children": [_node_to_dict(child) for child in node.children],
    }


def cmd_tree(ctx: AppContext) -> int:
    snapshot = ctx.collector().collect()
    by_pid = snapshot.by_pid()
    roots = build_process_tree(snapshot.processes, max_depth=ctx.args.depth)
    title = f"{len(snapshot.processes)} processes"
    if ctx.args.pid is not None:
        node = find_node(roots, ctx.args.pid)
        if node is None:
            raise ProcessNotFoundError(ctx.args.pid)
        roots = (node,)
        title = f"Subtree of PID {ctx.args.pid}"

    if ctx.json:
        write_json(envelope("tree", roots=[_node_to_dict(r) for r in roots]), sys.stdout)
        return ExitCode.OK
    ctx.console.print(process_tree(roots, by_pid, title=title))
    return ExitCode.OK


_ACTION_EXIT = {
    ActionOutcome.SUCCEEDED: ExitCode.OK,
    ActionOutcome.FAILED: ExitCode.ERROR,
    ActionOutcome.CANCELLED: ExitCode.CANCELLED,
    ActionOutcome.DENIED_BY_POLICY: ExitCode.BLOCKED_BY_POLICY,
}
_PROCESS_ACTION_TYPES = {
    "suspend": ActionType.SUSPEND_PROCESS,
    "resume": ActionType.RESUME_PROCESS,
    "terminate": ActionType.TERMINATE_PROCESS,
}


def _audit_recorder(ctx: AppContext) -> Callable[[ResponseAction], None]:
    """Append each response action to the audit log (opens/closes its own connection)."""

    def record(action: ResponseAction) -> None:
        try:
            store = ctx.open_store()
            try:
                store.record_action(action)
            finally:
                store.db.close()
        except (OSError, WinSentinelError) as exc:
            logger.warning("event=AUDIT_WRITE_FAILED error=%s", exc)

    return record


def _confirm(ctx: AppContext, prompt: str) -> bool:
    if getattr(ctx.args, "yes", False):
        return True
    if not sys.stdin.isatty():
        return False  # never act unattended without --yes
    ctx.err_console.print(Text(f"{prompt} [y/N] ", style="bold"), end="")
    try:
        answer = input().strip().lower()
    except EOFError:
        return False
    return answer in ("y", "yes")


def cmd_process_action(ctx: AppContext) -> int:
    args = ctx.args
    verb = args.action_verb
    action_type = _PROCESS_ACTION_TYPES[verb]
    controller = ProcessController(ctx.collector())
    process = controller.current(args.pid)  # raises ProcessNotFoundError (exit 4) if gone
    policy = ProtectionPolicy(frozenset(ctx.config.response.protected_processes))
    verdict = policy.evaluate(process)
    force = getattr(args, "force_protected", False)

    manager = ResponseManager(
        controller, policy, audit=_audit_recorder(ctx), requested_by=current_user()
    )
    reason = args.reason or "User-initiated response"

    # Show the target before acting (unless JSON).
    if not ctx.json:
        connections: list[CorrelatedConnection] = []
        with contextlib.suppress(Exception):
            snapshot = ctx.network_collector().collect()
            connections = [
                c
                for c in correlate(snapshot.connections, lookup_from_processes([process]))
                if c.process_key == process.process_key
            ]
        ctx.console.print(action_warning(verb, process, connections, verdict))

    if verdict.protected and not force and action_type is not ActionType.RESUME_PROCESS:
        action = manager.act_on_process(action_type, process, reason=reason, force_protected=False)
        ctx.console.print(action_result_text(action))
        if not ctx.quiet:
            ctx.err_console.print(
                Text("Refused. Re-run with --force-protected to override (dangerous).", style="red")
            )
        return _ACTION_EXIT[action.outcome]

    needs_confirm = (
        ctx.config.response.require_confirmation and action_type is not ActionType.RESUME_PROCESS
    )
    if needs_confirm and not _confirm(
        ctx, f"{verb.capitalize()} PID {process.pid} ({process.name})?"
    ):
        cancelled = ResponseAction(
            action_type=action_type,
            target=f"{process.name} (PID {process.pid})",
            process_key=process.process_key,
            pid=process.pid,
            reason=reason,
            requested_by=current_user(),
            outcome=ActionOutcome.CANCELLED,
        )
        _audit_recorder(ctx)(cancelled)
        ctx.console.print(action_result_text(cancelled))
        return ExitCode.CANCELLED

    action = manager.act_on_process(action_type, process, reason=reason, force_protected=force)
    if ctx.json:
        write_json(envelope("action", action=action), sys.stdout)
    else:
        ctx.console.print(action_result_text(action))
    return _ACTION_EXIT[action.outcome]


def cmd_firewall(ctx: AppContext) -> int:
    action = ctx.args.firewall_action
    controller = FirewallController()
    if action == "list":
        try:
            rules = controller.list_rules()
        except WinSentinelError as exc:
            raise WinSentinelError(str(exc)) from exc
        if ctx.json:
            write_json(envelope("firewall_rules", rules=rules), sys.stdout)
        elif rules:
            for name in rules:
                ctx.console.print(Text(name))
            ctx.console.print(Text(f"{len(rules)} WinSentinel firewall rules", style=colors.MUTED))
        else:
            ctx.console.print(Text("No WinSentinel firewall rules.", style=colors.MUTED))
        return ExitCode.OK

    manager = ResponseManager(
        ProcessController(ctx.collector()),
        ProtectionPolicy(frozenset(ctx.config.response.protected_processes)),
        firewall=controller,
        audit=_audit_recorder(ctx),
    )
    reason = ctx.args.reason or "User-initiated firewall block"
    if action == "unblock":
        if not _confirm(ctx, f"Remove firewall rule {ctx.args.rule_name}?"):
            ctx.console.print(Text("Cancelled.", style=colors.MUTED))
            return ExitCode.CANCELLED
        result = manager.firewall_unblock(ctx.args.rule_name, reason=reason)
        _maybe_record_firewall(ctx, result, removed=True)
        _print_action(ctx, result)
        return _ACTION_EXIT[result.outcome]

    spec, action_type = _firewall_spec(ctx.args)
    ctx.console.print(
        Text(
            "Will add an outbound BLOCK firewall rule for "
            f"{spec.target_type.lower()} {spec.target}."
        )
    )
    if not _confirm(ctx, f"Add block rule '{spec.rule_name}'?"):
        ctx.console.print(Text("Cancelled.", style=colors.MUTED))
        return ExitCode.CANCELLED
    result = manager.firewall_block(spec, action_type, reason=reason)
    _maybe_record_firewall(ctx, result, spec=spec)
    _print_action(ctx, result)
    if result.outcome is ActionOutcome.SUCCEEDED and not ctx.quiet and not ctx.json:
        ctx.console.print(
            Text(
                f'Reverse with: winsentinel firewall unblock "{spec.rule_name}"', style=colors.MUTED
            )
        )
    return _ACTION_EXIT[result.outcome]


def _firewall_spec(args: argparse.Namespace) -> tuple[FirewallRuleSpec, ActionType]:
    if args.firewall_action == "block-ip":
        return block_ip_spec(args.ip), ActionType.FIREWALL_BLOCK_IP
    if args.firewall_action == "block-port":
        return block_port_spec(args.port, args.protocol), ActionType.FIREWALL_BLOCK_PORT
    return block_program_spec(args.path), ActionType.FIREWALL_BLOCK_PROCESS


def _maybe_record_firewall(
    ctx: AppContext,
    action: ResponseAction,
    *,
    spec: FirewallRuleSpec | None = None,
    removed: bool = False,
) -> None:
    if action.outcome is not ActionOutcome.SUCCEEDED:
        return
    with contextlib.suppress(OSError, WinSentinelError):
        store = ctx.open_store()
        try:
            rule_name = str(action.details.get("rule_name"))
            if removed:
                store.mark_firewall_rule_removed(rule_name)
            elif spec is not None:
                store.record_firewall_rule(
                    rule_name, action.action_id, spec.target_type, spec.target, spec.direction
                )
        finally:
            store.db.close()


def _print_action(ctx: AppContext, action: ResponseAction) -> None:
    if ctx.json:
        write_json(envelope("action", action=action), sys.stdout)
    else:
        ctx.console.print(action_result_text(action))


def _prepare_database(ctx: AppContext) -> None:
    """Record config history and apply retention before the writer thread takes over the DB."""
    retention = ctx.config.retention
    store = ctx.open_store()
    try:
        if ctx.config_loaded:
            with contextlib.suppress(OSError):
                store.record_config(
                    str(ctx.config_path), ctx.config_path.read_text(encoding="utf-8")
                )
        deleted = store.apply_retention(
            retention.event_days, retention.alert_days, retention.action_days
        )
        if deleted and not ctx.quiet and not ctx.json:
            summary = ", ".join(f"{v} {k}" for k, v in deleted.items())
            ctx.err_console.print(Text(f"Retention: removed {summary}", style=colors.MUTED))
    finally:
        store.db.close()


def _parse_since(value: str | None) -> object:
    if value is None:
        return None
    return utc_now() - parse_duration(value)


def cmd_events(ctx: AppContext) -> int:
    store = ctx.open_store(read_only=True)
    try:
        rows = store.events(
            event_type=ctx.args.type.upper() if ctx.args.type else None,
            pid=ctx.args.pid,
            since=_parse_since(ctx.args.since),  # type: ignore[arg-type]
            limit=ctx.args.limit,
        )
    finally:
        store.db.close()
    if ctx.json:
        write_json(
            envelope("events", count=len(rows), events=[event_row_json(r) for r in rows]),
            sys.stdout,
        )
        return ExitCode.OK
    ctx.console.print(events_table(rows))
    if not ctx.quiet:
        ctx.console.print(Text(f"{len(rows)} events (most recent first)", style=colors.MUTED))
    return ExitCode.OK


def cmd_alerts(ctx: AppContext) -> int:
    action = getattr(ctx.args, "alerts_action", None)
    store = ctx.open_store(read_only=action != "set-status")
    try:
        if action == "set-status":
            ok = store.set_alert_status(ctx.args.alert_id, ctx.args.status.upper())
            if not ok:
                raise WinSentinelError(f"No alert matching {ctx.args.alert_id!r}")
            if not ctx.quiet:
                ctx.console.print(
                    Text(
                        f"Alert {ctx.args.alert_id} set to {ctx.args.status.upper()}",
                        style=colors.OK,
                    )
                )
            return ExitCode.OK
        if action == "show":
            row = store.alert(ctx.args.alert_id)
            if row is None:
                raise WinSentinelError(f"No alert matching {ctx.args.alert_id!r}")
            alert = alert_from_row(row)
            if ctx.json:
                write_json(envelope("alert", alert=alert), sys.stdout)
            else:
                ctx.console.print(alert_detail(alert))
            return ExitCode.OK
        since = (
            _parse_since("1d")
            if getattr(ctx.args, "today", False)
            else _parse_since(ctx.args.since)
        )
        rows = store.alerts(
            severity=ctx.args.severity.upper() if ctx.args.severity else None,
            status=ctx.args.status.upper() if ctx.args.status else None,
            since=since,  # type: ignore[arg-type]
            limit=ctx.args.limit,
        )
    finally:
        store.db.close()
    alerts = [alert_from_row(r) for r in rows]
    if ctx.json:
        write_json(envelope("alerts", count=len(alerts), alerts=alerts), sys.stdout)
        return ExitCode.OK
    if not alerts:
        ctx.console.print(
            Text("No alerts match. Run 'winsentinel monitor' to generate them.", style=colors.MUTED)
        )
        return ExitCode.OK
    ctx.console.print(alerts_table(alerts))
    if not ctx.quiet:
        ctx.console.print(
            Text(
                f"{len(alerts)} alerts · 'winsentinel alerts show <ID>' for detail · "
                "'winsentinel alerts set-status <ID> <STATUS>' to triage",
                style=colors.MUTED,
            )
        )
    return ExitCode.OK


def _capture_current(ctx: AppContext) -> list[BaselineItem]:
    processes = ctx.collector().collect().processes
    sockets = ctx.network_collector().collect()
    connections = correlate(sockets.connections, lookup_from_processes(processes))
    persistence = PersistenceCollector().collect()
    return capture_baseline(processes, connections, persistence)


def cmd_baseline(ctx: AppContext) -> int:
    action = ctx.args.baseline_action or "list"
    if action == "create":
        items = _capture_current(ctx)
        baseline_id = str(uuid.uuid4())
        expires = None
        days = (
            ctx.args.expires_days
            if ctx.args.expires_days is not None
            else ctx.config.baseline.max_age_days
        )
        if days > 0:
            expires = (utc_now() + timedelta(days=days)).isoformat()
        store = ctx.open_store()
        try:
            store.create_baseline(
                baseline_id,
                ctx.args.name or f"baseline {utc_now():%Y-%m-%d %H:%M}",
                created_by=current_user(),
                hostname=_hostname(),
                expires_at=expires,
                notes=None,
                items=[(i.kind.value, i.item_key, i.label, i.attributes) for i in items],
            )
        finally:
            store.db.close()
        if ctx.json:
            write_json(
                envelope("baseline_created", baseline_id=baseline_id, items=len(items)), sys.stdout
            )
        elif not ctx.quiet:
            ctx.console.print(
                Text(
                    f"Captured baseline {baseline_id[:8]} with {len(items)} items.", style=colors.OK
                )
            )
        return ExitCode.OK

    store = ctx.open_store(read_only=action in ("list", "compare", "show"))
    try:
        if action == "list":
            rows = store.baselines()
            if ctx.json:
                write_json(envelope("baselines", baselines=[dict(r) for r in rows]), sys.stdout)
            elif rows:
                ctx.console.print(baselines_table(rows))
            else:
                ctx.console.print(
                    Text(
                        "No baselines. Create one with 'winsentinel baseline create'.",
                        style=colors.MUTED,
                    )
                )
            return ExitCode.OK
        if action == "delete":
            ok = store.delete_baseline(ctx.args.baseline_id)
            if not ok:
                raise WinSentinelError(f"No baseline {ctx.args.baseline_id!r}")
            if not ctx.quiet:
                ctx.console.print(
                    Text(f"Deleted baseline {ctx.args.baseline_id}.", style=colors.OK)
                )
            return ExitCode.OK
        # compare / show
        target = getattr(ctx.args, "baseline", None) or getattr(ctx.args, "baseline_id", None)
        row = store.baseline(target) if target else store.latest_baseline()
        if row is None:
            raise WinSentinelError(
                "No baseline to compare against. Run 'winsentinel baseline create' first."
            )
        baseline_items = [
            BaselineItem(
                BaselineItemKind(r["kind"]), r["item_key"], r["label"], loads(r["attributes"])
            )
            for r in store.baseline_items(row["baseline_id"])
        ]
        expired = bool(row["expires_at"]) and datetime.fromisoformat(row["expires_at"]) < utc_now()
    finally:
        store.db.close()

    current = _capture_current(ctx)
    diffs = compare_baseline(baseline_items, current)
    grouped = diffs_by_kind(diffs)
    if ctx.json:
        write_json(
            envelope(
                "baseline_compare",
                baseline_id=row["baseline_id"],
                expired=expired,
                new_items=[
                    {"kind": d.kind.value, "label": d.label, "attributes": d.attributes}
                    for d in diffs
                ],
            ),
            sys.stdout,
        )
        return ExitCode.OK
    ctx.console.print(baseline_compare_view(row["name"], grouped, expired=expired))
    return ExitCode.OK


def cmd_allow(ctx: AppContext) -> int:
    action = ctx.args.allow_action
    if action == "list":
        store = ctx.open_store(read_only=True)
        try:
            rows = store.allowlist_entries()
        finally:
            store.db.close()
        if ctx.json:
            write_json(envelope("allowlist", entries=[dict(r) for r in rows]), sys.stdout)
        elif rows:
            ctx.console.print(allowlist_table(rows))
        else:
            ctx.console.print(Text("Allowlist is empty.", style=colors.MUTED))
        return ExitCode.OK
    if action == "remove":
        store = ctx.open_store()
        try:
            ok = store.remove_allowlist_entry(ctx.args.match_type.upper(), ctx.args.value)
        finally:
            store.db.close()
        if not ok:
            raise WinSentinelError(f"No allowlist entry {ctx.args.match_type} {ctx.args.value!r}")
        if not ctx.quiet:
            ctx.console.print(Text("Removed allowlist entry.", style=colors.OK))
        return ExitCode.OK
    if action == "name":
        raise InvalidInputError(
            "Allowlisting by process name is unsupported: a name is trivially spoofed by copying "
            "a file. Use 'allow exe <PATH>', 'allow sha256 <HASH>' or 'allow signer <NAME>'."
        )

    match_type, value = _allow_value(ctx.args)
    rule_ids = (
        ",".join(r.strip().upper() for r in ctx.args.rules.split(",")) if ctx.args.rules else None
    )
    expires = None
    if ctx.args.expires_days:
        expires = (utc_now() + timedelta(days=ctx.args.expires_days)).isoformat()
    store = ctx.open_store()
    try:
        store.add_allowlist_entry(
            match_type.value,
            value,
            rule_ids=rule_ids,
            reason=ctx.args.reason or "",
            created_by=current_user(),
            expires_at=expires,
        )
    finally:
        store.db.close()
    if not ctx.quiet:
        scope = f" for rules {rule_ids}" if rule_ids else " for all rules"
        ctx.console.print(Text(f"Allowlisted {match_type.value} {value}{scope}.", style=colors.OK))
        if match_type is AllowlistMatchType.EXE_PATH:
            ctx.err_console.print(
                Text(
                    "Note: path-based allowlisting is weaker than SHA256 — a different file placed "
                    "at this path would also be exempt.",
                    style=colors.MUTED,
                )
            )
    return ExitCode.OK


def _allow_value(args: argparse.Namespace) -> tuple[AllowlistMatchType, str]:
    if args.allow_action == "exe":
        from winsentinel.detection.paths import normalize

        return AllowlistMatchType.EXE_PATH, normalize(args.path)
    if args.allow_action == "sha256":
        value = args.hash.strip().lower()
        if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise InvalidInputError("SHA256 must be 64 hex characters")
        return AllowlistMatchType.SHA256, value
    return AllowlistMatchType.SIGNER, args.name


def _hostname() -> str:
    import socket

    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def cmd_persistence(ctx: AppContext) -> int:
    snapshot = PersistenceCollector().collect()
    items = list(snapshot.items)
    if ctx.args.kind:
        wanted = ctx.args.kind.upper()
        items = [i for i in items if i.kind.value == wanted]
    items.sort(key=lambda i: (i.kind.value, i.name.lower()))
    if ctx.json:
        write_json(
            envelope(
                "persistence",
                count=len(items),
                unavailable=list(snapshot.unavailable_sources),
                items=items,
            ),
            sys.stdout,
        )
        return ExitCode.OK
    ctx.console.print(persistence_table(items))
    if not ctx.quiet:
        note = f"{len(items)} autostart entries"
        if snapshot.unavailable_sources:
            note += f" · unavailable: {', '.join(snapshot.unavailable_sources)}"
        if not ctx.privileges.elevated:
            note += " · run elevated to see all scheduled tasks"
        ctx.console.print(Text(note, style=colors.MUTED))
    return ExitCode.OK


def cmd_logs(ctx: AppContext) -> int:
    path = ctx.config.general.resolved_log_path()
    if ctx.json:
        write_json(envelope("logs", path=str(path), exists=path.exists()), sys.stdout)
        return ExitCode.OK
    if not path.exists():
        ctx.console.print(Text(f"No log file at {path} yet.", style=colors.MUTED))
        return ExitCode.OK
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        raise WinSentinelError(f"Cannot read log file {path}: {exc}") from exc
    for line in lines[-ctx.args.tail :]:
        ctx.console.print(Text(sanitize_display(line)), highlight=False)
    return ExitCode.OK


def cmd_db(ctx: AppContext) -> int:
    action = ctx.args.db_action
    path = ctx.database_path()
    if action == "info":
        if not path.exists():
            if ctx.json:
                write_json(envelope("db_info", path=str(path), exists=False), sys.stdout)
            else:
                ctx.console.print(Text(f"No database at {path} yet.", style=colors.MUTED))
            return ExitCode.OK
        store = ctx.open_store(read_only=True)
        try:
            info = DatabaseInfo(str(path), store.db.version(), path.stat().st_size, store.counts())
        finally:
            store.db.close()
        if ctx.json:
            write_json(
                envelope(
                    "db_info",
                    path=info.path,
                    version=info.version,
                    size_bytes=info.size_bytes,
                    counts=info.counts,
                ),
                sys.stdout,
            )
        else:
            ctx.console.print(db_info_view(info))
        return ExitCode.OK
    # cleanup / vacuum modify the DB; refuse if a monitor is running.
    if _engine_running(ctx):
        raise WinSentinelError("A monitor is running; stop it before 'db cleanup' or 'db vacuum'.")
    store = ctx.open_store()
    try:
        if action == "cleanup":
            deleted = store.apply_retention(
                ctx.config.retention.event_days,
                ctx.config.retention.alert_days,
                ctx.config.retention.action_days,
            )
            message = ", ".join(f"{v} {k}" for k, v in deleted.items()) or "nothing to remove"
            if ctx.json:
                write_json(envelope("db_cleanup", deleted=deleted), sys.stdout)
            elif not ctx.quiet:
                ctx.console.print(Text(f"Cleanup: {message}", style=colors.OK))
        elif action == "vacuum":
            store.db.vacuum()
            if not ctx.quiet:
                ctx.console.print(Text("Database vacuumed.", style=colors.OK))
    finally:
        store.db.close()
    return ExitCode.OK


def _engine_running(ctx: AppContext) -> bool:
    status = StatusFile(default_status_path()).read()
    if status is None:
        return False
    alive = process_instance_alive(ctx.collector(), status.pid, status.process_key)
    return is_status_current(
        status,
        utc_now(),
        stale_after=timedelta(seconds=max(10.0, 5 * ctx.config.engine.status_interval_seconds)),
        process_alive=alive,
    )


def cmd_config(ctx: AppContext) -> int:
    action = ctx.args.config_action
    if action == "init":
        write_default_config(ctx.config_path, force=ctx.args.force)
        if not ctx.quiet:
            ctx.console.print(
                Text(f"Wrote default configuration to {ctx.config_path}", style=colors.OK)
            )
        return ExitCode.OK
    if action == "path":
        if ctx.json:
            write_json(
                envelope("config_path", path=str(ctx.config_path), exists=ctx.config_loaded),
                sys.stdout,
            )
        else:
            state = "loaded" if ctx.config_loaded else "not present — using built-in defaults"
            ctx.console.print(Text(f"{ctx.config_path}  ({state})"))
        return ExitCode.OK
    if action == "validate":
        # Loading already validated it (errors exit with USAGE before reaching here).
        if ctx.json:
            write_json(
                envelope(
                    "config_validation",
                    path=str(ctx.config_path),
                    exists=ctx.config_loaded,
                    valid=True,
                ),
                sys.stdout,
            )
        elif not ctx.quiet:
            message = (
                f"Configuration is valid: {ctx.config_path}"
                if ctx.config_loaded
                else f"No configuration file at {ctx.config_path}; built-in defaults are in effect."
            )
            ctx.console.print(Text(message, style=colors.OK))
        return ExitCode.OK
    # show
    if ctx.json:
        write_json(envelope("config", source=str(ctx.config_path), config=ctx.config), sys.stdout)
    else:
        ctx.console.print(JSON(ctx.config.model_dump_json()))
    return ExitCode.OK


# --------------------------------------------------------------------------------------------
# Parser
# --------------------------------------------------------------------------------------------


def _add_global_flags(parser: argparse.ArgumentParser, *, suppress: bool) -> None:
    """Global flags work before *and* after the subcommand.

    Sub-parsers register the same flags with ``default=SUPPRESS`` so an unspecified flag does not
    overwrite a value given before the subcommand.
    """

    def default(value: object) -> object:
        return argparse.SUPPRESS if suppress else value

    parser.add_argument(
        "--json", action="store_true", default=default(False), help="machine-readable JSON output"
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true", default=default(False), help="only essential output"
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        default=default(False),
        help="debug logging to stderr",
    )
    parser.add_argument(
        "--no-color", action="store_true", default=default(False), help="disable colours"
    )
    parser.add_argument(
        "--config", type=Path, default=default(None), metavar="PATH", help="path to config.toml"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="winsentinel",
        description=(
            "WinSentinel — see what your Windows system is doing, detect what shouldn't be "
            "happening, respond safely."
        ),
        epilog="Run 'winsentinel <command> --help' for command details.",
    )
    parser.add_argument(
        "--version", action="version", version=f"ThreatLens {__version__} (winsentinel core)"
    )
    _add_global_flags(parser, suppress=False)

    common = argparse.ArgumentParser(add_help=False)
    _add_global_flags(common, suppress=True)
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    p = sub.add_parser(
        "processes",
        parents=[common],
        help="list running processes",
        description=(
            "List running processes. Fields the current token cannot read are shown as "
            "<access denied>."
        ),
    )
    p.add_argument(
        "--sort", choices=sorted(SORT_KEYS), default="cpu", help="sort order (default: cpu)"
    )
    p.add_argument("--limit", type=_positive_int, help="show at most N processes")
    p.add_argument(
        "--name", help="filter: process name contains TEXT (case-insensitive)", metavar="TEXT"
    )
    p.add_argument(
        "--user", help="filter: username contains TEXT (case-insensitive)", metavar="TEXT"
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="add SHA256 and Authenticode signature (slower on first run)",
    )
    p.add_argument(
        "--sample",
        type=_bounded_float(0.0, MAX_CPU_SAMPLE_SECONDS),
        default=DEFAULT_CPU_SAMPLE_SECONDS,
        metavar="SECONDS",
        help=f"CPU sampling window; 0 skips CPU (default: {DEFAULT_CPU_SAMPLE_SECONDS})",
    )
    p.set_defaults(handler=cmd_processes)

    p = sub.add_parser(
        "process",
        parents=[common],
        help="show one process in detail",
        description="Show identity, image, signature, resources and lineage of one process.",
    )
    p.add_argument("pid", type=_pid_arg, help="process ID")
    p.add_argument(
        "--no-verify", action="store_true", help="skip hashing and signature verification"
    )
    p.add_argument(
        "--sample",
        type=_bounded_float(0.0, MAX_CPU_SAMPLE_SECONDS),
        default=DEFAULT_CPU_SAMPLE_SECONDS,
        metavar="SECONDS",
        help=f"CPU sampling window (default: {DEFAULT_CPU_SAMPLE_SECONDS})",
    )
    p.set_defaults(handler=cmd_process)

    p = sub.add_parser(
        "tree",
        parents=[common],
        help="show the process tree",
        description=(
            "Show parent/child relationships. A parent is only accepted if it was created before "
            "the child, so reused PIDs never produce false lineage."
        ),
    )
    p.add_argument("--pid", type=_pid_arg, help="show only the subtree rooted at PID")
    p.add_argument("--depth", type=_positive_int, default=64, help="maximum depth (default: 64)")
    p.set_defaults(handler=cmd_tree)

    state_choices = sorted(s.value for s in ConnectionState)

    p = sub.add_parser(
        "network",
        parents=[common],
        help="list all sockets with their owning processes",
        description=(
            "List TCP/UDP sockets (IPv4 and IPv6) with owning process, inferred direction and "
            "address scope. Each socket is joined to the process instance that existed when the "
            "socket was created, so reused PIDs are never blamed."
        ),
    )
    p.add_argument("--protocol", choices=["tcp", "udp"], help="only this protocol")
    p.add_argument("--state", choices=state_choices, metavar="STATE", help="only this TCP state")
    p.add_argument("--pid", type=_pid_arg, help="only sockets owned by PID")
    p.add_argument("--external", action="store_true", help="only connections to public addresses")
    p.add_argument(
        "--listening", action="store_true", help="only listening TCP / bound UDP sockets"
    )
    p.set_defaults(handler=cmd_network)

    p = sub.add_parser(
        "connections",
        parents=[common],
        help="active connections grouped by process",
        description="Show non-listening connections grouped under the process that owns them.",
    )
    p.add_argument("--protocol", choices=["tcp", "udp"], help="only this protocol")
    p.add_argument("--pid", type=_pid_arg, help="only connections owned by PID")
    p.add_argument("--external", action="store_true", help="only connections to public addresses")
    p.add_argument("--verify", action="store_true", help="add signature status for each process")
    p.set_defaults(handler=cmd_connections)

    p = sub.add_parser(
        "inspect",
        parents=[common],
        help="investigate one process: image, lineage, network",
        description=(
            "Everything known about one process: identity, image hash and signature, resources, "
            "verified ancestry and children, owned sockets, and external communication chains."
        ),
    )
    p.add_argument("pid", type=_pid_arg, help="process ID")
    p.add_argument(
        "--sample",
        type=_bounded_float(0.0, MAX_CPU_SAMPLE_SECONDS),
        default=DEFAULT_CPU_SAMPLE_SECONDS,
        metavar="SECONDS",
        help=f"CPU sampling window (default: {DEFAULT_CPU_SAMPLE_SECONDS})",
    )
    p.set_defaults(handler=cmd_inspect)

    p = sub.add_parser(
        "monitor",
        parents=[common],
        help="run the monitoring engine and stream live activity",
        description=(
            "Run the engine: poll processes and sockets, enrich executables in the background, "
            "and stream changes as they happen. Processes and sockets that already exist at "
            "startup are inventory, not new activity. Stop with Ctrl+C."
        ),
    )
    p.add_argument(
        "--interval",
        type=_bounded_float(0.5, 60.0),
        metavar="SECONDS",
        help="polling interval (default: general.refresh_interval_seconds)",
    )
    p.add_argument(
        "--duration",
        type=_bounded_float(0.1, 7 * 24 * 3600.0),
        metavar="SECONDS",
        help="stop automatically after SECONDS",
    )
    p.add_argument(
        "--events",
        metavar="LIST",
        help=(
            "comma-separated categories to show: "
            f"{', '.join(ALL_CATEGORIES)}, all (default: {', '.join(sorted(DEFAULT_CATEGORIES))})"
        ),
    )
    p.add_argument(
        "--loopback", action="store_true", help="include loopback (127.0.0.1/::1) connections"
    )
    p.add_argument(
        "--no-store", action="store_true", help="do not persist events/alerts to the database"
    )
    p.add_argument(
        "--dashboard", action="store_true", help="force the live dashboard (default on a terminal)"
    )
    p.add_argument(
        "--stream", action="store_true", help="line-by-line event stream instead of the dashboard"
    )
    p.set_defaults(handler=cmd_monitor)

    p = sub.add_parser(
        "events",
        parents=[common],
        help="query recorded security events from the database",
        description="Show events recorded by past 'monitor' runs, most recent first.",
    )
    p.add_argument("--type", metavar="TYPE", help="only this event type, e.g. PROCESS_STARTED")
    p.add_argument("--pid", type=_pid_arg, help="only events for PID")
    p.add_argument(
        "--since", metavar="DURATION", help="only events within DURATION (e.g. 30m, 2h, 7d)"
    )
    p.add_argument("--limit", type=_positive_int, default=100, help="max rows (default: 100)")
    p.set_defaults(handler=cmd_events)

    p = sub.add_parser(
        "alerts",
        parents=[common],
        help="list, show or triage security alerts",
        description=(
            "Alerts are combined, scored signals recorded by 'monitor' — for investigation, "
            "not verdicts."
        ),
    )
    alerts_sub = p.add_subparsers(dest="alerts_action", metavar="<action>")
    listing = alerts_sub.add_parser("list", parents=[common], help="list alerts (default)")
    severities = ["normal", "low", "medium", "high", "critical"]
    statuses = ["new", "acknowledged", "investigating", "resolved", "ignored"]
    for target in (p, listing):
        target.add_argument("--severity", choices=severities, help="exact severity")
        target.add_argument("--status", choices=statuses)
        target.add_argument("--since", metavar="DURATION", help="alerts created within DURATION")
        target.add_argument("--today", action="store_true", help="alerts from the last 24h")
        target.add_argument("--limit", type=_positive_int, default=100, help="max rows")
    show = alerts_sub.add_parser("show", parents=[common], help="show one alert in detail")
    show.add_argument("alert_id", metavar="ALERT_ID", help="alert id (8-char prefix accepted)")
    status_cmd = alerts_sub.add_parser("set-status", parents=[common], help="triage an alert")
    status_cmd.add_argument("alert_id", metavar="ALERT_ID")
    status_cmd.add_argument("status", choices=statuses)
    p.set_defaults(handler=cmd_alerts)

    for verb, help_text in (
        ("suspend", "freeze a process (reversible) while you investigate"),
        ("resume", "resume a suspended process"),
        ("terminate", "terminate a process (irreversible, requires confirmation)"),
    ):
        p = sub.add_parser(
            verb,
            parents=[common],
            help=help_text,
            description=(
                f"{help_text.capitalize()}. Shows the process (path, user, network) and asks for "
                "confirmation. Protected system processes are refused unless --force-protected."
            ),
        )
        p.add_argument("pid", type=_pid_arg, help="process ID")
        p.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
        p.add_argument("--reason", help="reason recorded in the audit log")
        if verb != "resume":
            p.add_argument(
                "--force-protected",
                action="store_true",
                help="override the protected-process safety check (dangerous)",
            )
        p.set_defaults(handler=cmd_process_action, action_verb=verb)

    p = sub.add_parser(
        "firewall",
        parents=[common],
        help="add or remove Windows Firewall block rules (requires admin)",
        description=(
            "Block outbound traffic by IP, port or program via the Windows Firewall. WinSentinel "
            "only adds rules named 'WinSentinel:…' and only removes those, so it can never weaken "
            "the firewall or touch your own rules. Every change is confirmed and logged."
        ),
    )
    fw_sub = p.add_subparsers(dest="firewall_action", metavar="<action>", required=True)
    fw_list = fw_sub.add_parser("list", parents=[common], help="list WinSentinel firewall rules")  # noqa: F841
    fw_ip = fw_sub.add_parser("block-ip", parents=[common], help="block outbound to an IP")
    fw_ip.add_argument("ip", help="IPv4 or IPv6 address")
    fw_port = fw_sub.add_parser("block-port", parents=[common], help="block an outbound port")
    fw_port.add_argument("port", type=int, help="port number (0-65535)")
    fw_port.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
    fw_prog = fw_sub.add_parser(
        "block-process", parents=[common], help="block a program's outbound traffic"
    )
    fw_prog.add_argument("path", help="full path to the executable")
    fw_unblock = fw_sub.add_parser(
        "unblock", parents=[common], help="remove a WinSentinel firewall rule"
    )
    fw_unblock.add_argument("rule_name", help="rule name (from 'firewall list')")
    for target in (fw_ip, fw_port, fw_prog, fw_unblock):
        target.add_argument("--yes", "-y", action="store_true", help="skip the confirmation prompt")
        target.add_argument("--reason", help="reason recorded in the audit log")
    p.set_defaults(handler=cmd_firewall)

    p = sub.add_parser(
        "baseline",
        parents=[common],
        help="capture a known-good baseline and compare against it",
        description=(
            "Capture what is running, listening and persisting now, then later compare to surface "
            "exactly what is new since that known-good moment."
        ),
    )
    base_sub = p.add_subparsers(dest="baseline_action", metavar="<action>")
    create = base_sub.add_parser("create", parents=[common], help="capture a new baseline")
    create.add_argument("--name", help="a label for the baseline")
    create.add_argument(
        "--expires-days", type=int, help="days until the baseline expires (0 = never)"
    )
    compare = base_sub.add_parser(
        "compare", parents=[common], help="show what is new since a baseline"
    )
    compare.add_argument("--baseline", metavar="ID", help="baseline id (default: most recent)")
    base_sub.add_parser("list", parents=[common], help="list baselines")
    delete = base_sub.add_parser("delete", parents=[common], help="delete a baseline")
    delete.add_argument("baseline_id", metavar="ID")
    p.set_defaults(handler=cmd_baseline)

    p = sub.add_parser(
        "allow",
        parents=[common],
        help="allowlist known-good programs so they stop generating detections",
        description=(
            "Mark a program as known-good by SHA256 (strongest), signer, or full path. Name-based "
            "allowlisting is unsupported because a name is trivially spoofed."
        ),
    )
    allow_sub = p.add_subparsers(dest="allow_action", metavar="<action>", required=True)
    a_exe = allow_sub.add_parser("exe", parents=[common], help="allowlist by full executable path")
    a_exe.add_argument("path", help="full path to the executable")
    a_sha = allow_sub.add_parser(
        "sha256", parents=[common], help="allowlist by SHA256 (recommended)"
    )
    a_sha.add_argument("hash", help="64-character SHA256")
    a_signer = allow_sub.add_parser(
        "signer", parents=[common], help="allowlist by valid-signature publisher"
    )
    a_signer.add_argument("name", help="exact signer/publisher name")
    a_name = allow_sub.add_parser("name", parents=[common], help="(rejected — explains why)")
    a_name.add_argument("name", nargs="?")
    allow_sub.add_parser("list", parents=[common], help="list allowlist entries")
    a_remove = allow_sub.add_parser("remove", parents=[common], help="remove an allowlist entry")
    a_remove.add_argument("match_type", choices=["exe_path", "sha256", "signer"])
    a_remove.add_argument("value")
    for target in (a_exe, a_sha, a_signer):
        target.add_argument(
            "--rules", metavar="IDS", help="comma-separated rule IDs (default: all rules)"
        )
        target.add_argument("--reason", help="why this is allowlisted")
        target.add_argument("--expires-days", type=int, help="days until the entry expires")
    p.set_defaults(handler=cmd_allow)

    p = sub.add_parser(
        "persistence",
        parents=[common],
        help="list autostart / persistence entries",
        description=(
            "List where programs are configured to run automatically: registry Run keys, Startup "
            "folders, scheduled tasks and auto-start services. Read-only; nothing is modified."
        ),
    )
    p.add_argument(
        "--kind",
        choices=["registry_run", "startup_folder", "scheduled_task", "service"],
        help="only this kind of entry",
    )
    p.set_defaults(handler=cmd_persistence)

    p = sub.add_parser("logs", parents=[common], help="show the tail of the log file")
    p.add_argument("--tail", type=_positive_int, default=50, help="lines to show (default: 50)")
    p.set_defaults(handler=cmd_logs)

    p = sub.add_parser("db", parents=[common], help="inspect or maintain the database")
    db_sub = p.add_subparsers(dest="db_action", metavar="<action>", required=True)
    db_sub.add_parser("info", parents=[common], help="schema version, size and row counts")
    db_sub.add_parser("cleanup", parents=[common], help="apply retention now (removes old rows)")
    db_sub.add_parser("vacuum", parents=[common], help="reclaim space (VACUUM)")
    p.set_defaults(handler=cmd_db)

    p = sub.add_parser(
        "status",
        parents=[common],
        help="engine health, system info and a collector self-test",
        description=(
            "Show whether a monitor is running (and its component health, queue and load), "
            "plus a quick self-test of each collector on this machine."
        ),
    )
    p.add_argument("--no-self-test", action="store_true", help="skip running the collectors")
    p.set_defaults(handler=cmd_status)

    p = sub.add_parser(
        "rules",
        parents=[common],
        help="list detection rules or show one in detail",
        description=(
            "List detection rules with their category, score contribution and confidence, or "
            "show a rule's rationale, false positives and recommendation."
        ),
    )
    rules_sub = p.add_subparsers(dest="rules_action", metavar="<action>")
    rules_sub.add_parser("list", parents=[common], help="list all rules (default)")
    show = rules_sub.add_parser("show", parents=[common], help="show one rule")
    show.add_argument("rule_id", metavar="RULE_ID", help="e.g. PROC-006")
    p.set_defaults(handler=cmd_rules)

    p = sub.add_parser("config", parents=[common], help="inspect or create configuration")
    config_sub = p.add_subparsers(dest="config_action", metavar="<action>", required=True)
    config_sub.add_parser("path", parents=[common], help="print the configuration file path")
    config_sub.add_parser("show", parents=[common], help="print the effective configuration")
    config_sub.add_parser("validate", parents=[common], help="validate the configuration file")
    init = config_sub.add_parser("init", parents=[common], help="write a commented default config")
    init.add_argument("--force", action="store_true", help="overwrite an existing file")
    p.set_defaults(handler=cmd_config)

    return parser


# --------------------------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(raw)
    implicit_dashboard = False
    if not getattr(args, "handler", None):
        # Launched with no command: on an interactive terminal (e.g. double-clicking
        # ThreatLens.exe) open the live dashboard; otherwise print help.
        if not raw and sys.stdout.isatty() and sys.stdin.isatty():
            args = parser.parse_args(["monitor"])
            implicit_dashboard = True
        else:
            parser.print_help()
            return ExitCode.USAGE

    # Force UTF-8 so box-drawing and status glyphs render in any console or when redirected to a
    # file (Windows would otherwise default stdout to the legacy ANSI code page and crash on '●').
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            with contextlib.suppress(Exception):
                reconfigure(encoding="utf-8", errors="replace")

    code = _dispatch(args)
    if implicit_dashboard and code not in (ExitCode.OK, EXIT_INTERRUPTED):
        # A double-clicked console window closes as soon as the process exits; keep the error
        # on screen long enough to be read.
        with contextlib.suppress(EOFError, KeyboardInterrupt):
            input("\nPress Enter to close...")
    return code


def _dispatch(args: argparse.Namespace) -> int:
    no_color = bool(args.no_color) or args.json
    console = Console(no_color=no_color, highlight=False, soft_wrap=False)
    err_console = Console(stderr=True, no_color=no_color, highlight=False)
    configure_logging(verbose=args.verbose, quiet=args.quiet)

    try:
        if args.handler is cmd_config and args.config_action == "init":
            # `init` creates the file, so it must not require (or trust) an existing one.
            config, config_path, loaded = Config(), args.config or default_config_path(), False
        else:
            config, config_path, loaded = load_config(args.config)
        configure_logging(config.general.log_level, verbose=args.verbose, quiet=args.quiet)
        ctx = AppContext(
            args=args,
            config=config,
            config_path=config_path,
            config_loaded=loaded,
            console=console,
            err_console=err_console,
            privileges=detect_privileges(),
        )
        return int(args.handler(ctx))
    except WinSentinelError as exc:
        if args.json:
            write_json(envelope("error", error=type(exc).__name__, message=str(exc)), sys.stdout)
        err_console.print(Text(f"error: {sanitize_display(str(exc))}", style=colors.ERROR))
        return int(exc.exit_code)
    except KeyboardInterrupt:
        err_console.print(Text("interrupted", style=colors.MUTED))
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        return ExitCode.OK  # e.g. `winsentinel processes | Select-Object -First 5`


if __name__ == "__main__":
    raise SystemExit(main())
