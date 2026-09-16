"""Rules about network behaviour, evaluated in the context of the owning process.

None of these rules treats a port, an address or "unknown" as malicious by itself. Each one
stays silent for executables in trusted locations or with a valid signature, and the weakest
signals (NET-001, NET-004) carry the lowest scores so they matter only in combination.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from datetime import datetime
from typing import Final

from threatlens.core.interfaces import StateView
from threatlens.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    Evidence,
    ProcessInfo,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
)
from threatlens.detection.paths import normalize
from threatlens.detection.rules.base import (
    MAX_EVIDENCE_CONNECTIONS,
    ConnectionFacts,
    EnrichmentDeferral,
    Rule,
    enrichment_pending,
    inferred,
    observed,
)
from threatlens.detection.settings import DetectionSettings
from threatlens.utils.lru import BoundedLRUCache

MAX_TRACKED_PROCESSES: Final = 2048


class _DeferringNetworkRule(Rule):
    """Evaluates connection events now if the owner's signature is known, else on enrichment."""

    def __init__(self, settings: DetectionSettings) -> None:
        super().__init__(settings)
        self._deferred = EnrichmentDeferral()

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        if event.event_type is EventType.PROCESS_ENRICHED:
            process = self.subject(event, state)
            parked = self._deferred.release(event.process_key) if event.process_key else []
            if process is None or not parked:
                return None
            return self.judge(process, parked, event, state)
        facts = ConnectionFacts.from_data(event.data)
        if facts.process_key is None:
            return None
        process = state.process(facts.process_key)
        if process is None or not self.is_candidate(facts, event):
            return None
        if enrichment_pending(process):
            self._deferred.park(facts.process_key, facts)
            return None
        return self.judge(process, [facts], event, state)

    def is_candidate(self, facts: ConnectionFacts, event: SecurityEvent) -> bool:
        raise NotImplementedError

    def judge(
        self,
        process: ProcessInfo,
        candidates: list[ConnectionFacts],
        event: SecurityEvent,
        state: StateView,
    ) -> DetectionResult | None:
        raise NotImplementedError


class NewProcessExternalConnection(_DeferringNetworkRule):
    meta = RuleMetadata(
        rule_id="PROC-004",
        name="New process connects to the internet immediately after starting",
        description=(
            "An executable outside trusted locations and without a valid signature opened an "
            "outbound connection to a public address within seconds of starting."
        ),
        rationale=(
            "Droppers, loaders and remote-access tools typically phone home the moment they run. "
            "The delay is measured with kernel timestamps (process creation vs. socket creation), "
            "so it is exact regardless of polling interval."
        ),
        category=RuleCategory.NETWORK,
        event_types=(
            EventType.CONNECTION_OPENED,
            EventType.CONNECTION_DISCOVERED,
            EventType.PROCESS_ENRICHED,
        ),
        base_score=20,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1071", "T1105"),
        false_positives=(
            "Unsigned self-updating tools that check for updates on launch",
            "Portable applications that sync immediately (chat clients, game launchers)",
        ),
        recommendation=(
            "Identify the remote address's owner and what the process sent; check how the "
            "executable arrived on the machine."
        ),
    )

    def is_candidate(self, facts: ConnectionFacts, event: SecurityEvent) -> bool:
        return facts.is_public_outbound

    def judge(
        self,
        process: ProcessInfo,
        candidates: list[ConnectionFacts],
        event: SecurityEvent,
        state: StateView,
    ) -> DetectionResult | None:
        if self.is_excluded_by_trust(process) or process.create_time is None:
            return None
        window = self.settings.correlation_window
        hits: list[tuple[ConnectionFacts, float]] = []
        for facts in candidates:
            if not facts.is_public_outbound or facts.created_at is None:
                continue
            delay = (facts.created_at - process.create_time).total_seconds()
            if 0 <= delay <= window.total_seconds():
                hits.append((facts, delay))
        if not hits:
            return None
        signature = process.signature.status.value if process.signature else "UNKNOWN"
        evidence: list[Evidence] = [
            observed(
                f"Process created at {process.create_time.isoformat()}",
                "create_time",
                process.create_time.isoformat(),
            ),
        ]
        evidence.extend(
            observed(
                f"{f.protocol} connection to {f.endpoint} created {delay:.1f}s after the process "
                "started",
                "remote",
                f.endpoint,
            )
            for f, delay in hits[:MAX_EVIDENCE_CONNECTIONS]
        )
        evidence.append(
            inferred(
                f"Executable is outside trusted locations and its signature is {signature}",
                "exe",
                process.exe,
            )
        )
        first = hits[0]
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"connected to {first[0].endpoint} {first[1]:.1f}s after starting",
            event=event,
            network=[f.context() for f, _ in hits],
        )


class UncommonRemotePort(_DeferringNetworkRule):
    meta = RuleMetadata(
        rule_id="NET-004",
        name="Outbound connection to an uncommon port",
        description=(
            "An executable outside trusted locations and without a valid signature connected to a "
            "public address on a port outside the configured common-port list."
        ),
        rationale=(
            "Remote-access tools and command-and-control channels often use non-standard ports. "
            "Port numbers prove nothing — any service can run on any port — so this is the "
            "weakest network signal and only adds context to others."
        ),
        category=RuleCategory.NETWORK,
        event_types=(
            EventType.CONNECTION_OPENED,
            EventType.CONNECTION_DISCOVERED,
            EventType.PROCESS_ENRICHED,
        ),
        base_score=10,
        confidence=Confidence.LOW,
        mitre_techniques=("T1571",),
        false_positives=(
            "Games, VoIP, peer-to-peer and development tools using their own ports",
            "Self-hosted services on non-standard ports",
        ),
        recommendation=(
            "Check whether the destination and port are expected for this application; extend "
            "detection.common_remote_ports if they are."
        ),
    )

    def is_candidate(self, facts: ConnectionFacts, event: SecurityEvent) -> bool:
        return (
            facts.is_public_outbound
            and facts.protocol == "TCP"
            and facts.remote_port is not None
            and facts.remote_port not in self.settings.common_remote_ports
        )

    def judge(
        self,
        process: ProcessInfo,
        candidates: list[ConnectionFacts],
        event: SecurityEvent,
        state: StateView,
    ) -> DetectionResult | None:
        if self.is_excluded_by_trust(process):
            return None
        hits = [f for f in candidates if self.is_candidate(f, event)]
        if not hits:
            return None
        ports = sorted({f.remote_port for f in hits if f.remote_port is not None})
        evidence: list[Evidence] = [
            observed(f"{f.protocol} connection to {f.endpoint}", "remote", f.endpoint)
            for f in hits[:MAX_EVIDENCE_CONNECTIONS]
        ]
        evidence.append(
            inferred(
                f"Port(s) {', '.join(map(str, ports))} are not in detection.common_remote_ports; "
                "an uncommon port alone is weak evidence"
            )
        )
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"connection to uncommon port {ports[0]}",
            event=event,
            network=[f.context() for f in hits],
            dedup_key=",".join(map(str, ports)),
        )


class FirstSeenExecutableOutbound(_DeferringNetworkRule):
    meta = RuleMetadata(
        rule_id="NET-001",
        name="Previously unseen executable connects to the internet",
        description=(
            "An executable that has not communicated since monitoring began makes its first "
            "outbound connection to a public address, and it is outside trusted locations without "
            "a valid signature."
        ),
        rationale=(
            "Programs that were already communicating when monitoring started are part of the "
            "inventory. A new, unsigned program in a user-writable location that starts talking "
            "to the internet deserves a look. Unknown is not malicious, so this scores low."
        ),
        category=RuleCategory.NETWORK,
        event_types=(
            EventType.CONNECTION_DISCOVERED,
            EventType.CONNECTION_OPENED,
            EventType.PROCESS_ENRICHED,
        ),
        base_score=10,
        confidence=Confidence.LOW,
        mitre_techniques=("T1071",),
        false_positives=("Any newly installed or first-run unsigned application",),
        recommendation=(
            "Confirm the program is expected; if so, allowlist it by path or hash (baselines "
            "arrive in a later phase)."
        ),
    )

    def __init__(self, settings: DetectionSettings) -> None:
        super().__init__(settings)
        self._seen: BoundedLRUCache[str, bool] = BoundedLRUCache(10_000)

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        if event.event_type is EventType.CONNECTION_DISCOVERED:
            exe = self._exe_for(ConnectionFacts.from_data(event.data), state)
            if exe is not None:
                self._seen.put(normalize(exe), True)  # inventory: already communicating
            return None
        return super().evaluate(event, state)

    def is_candidate(self, facts: ConnectionFacts, event: SecurityEvent) -> bool:
        return event.event_type is not EventType.CONNECTION_DISCOVERED and facts.is_public_outbound

    def judge(
        self,
        process: ProcessInfo,
        candidates: list[ConnectionFacts],
        event: SecurityEvent,
        state: StateView,
    ) -> DetectionResult | None:
        if process.exe is None:
            return None
        key = normalize(process.exe)
        if self._seen.get(key):
            return None
        self._seen.put(key, True)
        if self.is_excluded_by_trust(process):
            return None
        first = candidates[0]
        evidence = [
            observed(
                "First outbound connection by this executable since monitoring began: "
                f"{first.endpoint}",
                "remote",
                first.endpoint,
            ),
            inferred(
                "Executable is outside trusted locations and has no valid signature",
                "exe",
                process.exe,
            ),
        ]
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"first connection to {first.endpoint}",
            event=event,
            network=[first.context()],
        )

    @staticmethod
    def _exe_for(facts: ConnectionFacts, state: StateView) -> str | None:
        if facts.exe:
            return facts.exe
        process = state.process(facts.process_key) if facts.process_key else None
        return process.exe if process else None


class NewListeningPort(Rule):
    meta = RuleMetadata(
        rule_id="NET-002",
        name="New listening port reachable from the network",
        description=(
            "A process outside trusted locations started listening on a non-loopback address "
            "after monitoring began."
        ),
        rationale=(
            "A listener bound to all interfaces or a LAN address accepts inbound connections — "
            "exactly what a backdoor or bind shell needs. Loopback listeners (local IPC) and "
            "services in trusted locations are not flagged."
        ),
        category=RuleCategory.NETWORK,
        event_types=(EventType.LISTENER_OPENED,),
        base_score=20,
        confidence=Confidence.LOW,
        mitre_techniques=("T1571",),
        false_positives=(
            "Development servers, media casting and LAN discovery in user-installed apps",
            "Peer-to-peer and game clients",
        ),
        recommendation=(
            "Check which process owns the port, whether Windows Firewall allows it inbound, and "
            "whether the user expects a server here."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        facts = ConnectionFacts.from_data(event.data)
        if (
            facts.local_scope == "LOOPBACK"
            or facts.attribution != "ATTRIBUTED"
            or facts.process_key is None
        ):
            return None
        process = state.process(facts.process_key)
        if process is None or process.exe is None or self.settings.paths.is_trusted(process.exe):
            return None
        bind = (
            "all interfaces"
            if facts.local_scope == "UNSPECIFIED"
            else f"address {facts.local_address}"
        )
        evidence = [
            observed(
                f"{facts.protocol} listener opened on port {facts.local_port} ({bind})",
                "local",
                f"{facts.local_address}:{facts.local_port}",
            ),
            inferred("Other hosts can connect unless Windows Firewall blocks the port"),
            observed("Owning executable", "exe", process.exe),
        ]
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"listening on {facts.protocol} port {facts.local_port} ({bind})",
            event=event,
            network=[facts.context()],
            dedup_key=f"{facts.protocol}:{facts.local_port}",
        )


class HighFrequencyOutbound(Rule):
    meta = RuleMetadata(
        rule_id="NET-003",
        name="High-frequency or scan-like outbound connections",
        description=(
            "A process outside trusted locations opened an unusually large number of outbound "
            "connections, contacted many hosts on the same port, or made many unanswered attempts "
            "within a short window."
        ),
        rationale=(
            "Worm-like propagation, port scanning and beaconing retries produce bursts that "
            "ordinary desktop applications outside Program Files rarely do. Polling only observes "
            "connections alive at poll time, so real counts are at least as high as reported."
        ),
        category=RuleCategory.NETWORK,
        event_types=(EventType.CONNECTION_OPENED,),
        base_score=20,
        confidence=Confidence.LOW,
        mitre_techniques=("T1046", "T1071"),
        false_positives=(
            "Download managers, torrent clients and crawlers",
            "Network inventory tools run by administrators",
        ),
        recommendation=(
            "Look at the destinations in the evidence: many hosts on one port suggests scanning; "
            "repeated attempts to one host suggests a failing beacon."
        ),
    )

    def __init__(self, settings: DetectionSettings) -> None:
        super().__init__(settings)
        self._history: OrderedDict[str, deque[tuple[datetime, str, int | None, str]]] = (
            OrderedDict()
        )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        facts = ConnectionFacts.from_data(event.data)
        if (
            facts.direction != "OUTBOUND"
            or facts.remote_scope == "LOOPBACK"
            or facts.process_key is None
        ):
            return None
        process = state.process(facts.process_key)
        if process is None or process.exe is None or self.settings.paths.is_trusted(process.exe):
            return None

        history = self._history.setdefault(facts.process_key, deque())
        self._history.move_to_end(facts.process_key)
        while len(self._history) > MAX_TRACKED_PROCESSES:
            self._history.popitem(last=False)
        now = event.timestamp
        history.append((now, facts.remote_address or "", facts.remote_port, facts.state))
        cutoff = now - self.settings.burst_window
        while history and history[0][0] < cutoff:
            history.popleft()

        window = int(self.settings.burst_window.total_seconds())
        hosts_per_port: dict[int | None, set[str]] = {}
        for _, address, port, _ in history:
            hosts_per_port.setdefault(port, set()).add(address)
        port, hosts = max(hosts_per_port.items(), key=lambda item: len(item[1]))
        attempts = sum(1 for *_, state_name in history if state_name == "SYN_SENT")

        if len(hosts) >= self.settings.fanout_threshold:
            kind, detail = (
                "fanout",
                f"{len(hosts)} different hosts contacted on port {port} within {window}s",
            )
            techniques: tuple[str, ...] = ("T1046",)
        elif attempts >= self.settings.failed_connection_threshold:
            kind, detail = (
                "attempts",
                f"{attempts} connection attempts still waiting for a reply within {window}s",
            )
            techniques = ("T1071",)
        elif len(history) >= self.settings.burst_threshold:
            kind, detail = "burst", f"{len(history)} new outbound connections within {window}s"
            techniques = ("T1071",)
        else:
            return None
        evidence = [
            observed(
                detail,
                "count",
                len(hosts)
                if kind == "fanout"
                else (attempts if kind == "attempts" else len(history)),
            ),
            inferred(
                "Rate observed by polling; short-lived connections between polls are not counted"
            ),
        ]
        return self.result(
            process=process,
            evidence=evidence,
            detail=detail,
            event=event,
            dedup_key=kind,
            mitre=techniques,
        )
