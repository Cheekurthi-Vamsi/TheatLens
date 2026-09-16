"""Core domain models.

Design notes
------------
* Models are **immutable** (``frozen=True``) so a snapshot handed to a rule, the UI or storage
  cannot be mutated behind another component's back.
* ``extra="forbid"`` makes schema drift a loud error instead of silently-ignored data.
* Missing data is explicit: :attr:`ProcessInfo.unavailable` records *why* a field is ``None``.
* One module per domain; everything is re-exported here so callers import from
  ``threatlens.core.models``.
"""

from threatlens.core.models.action import ActionOutcome, ActionType, ResponseAction
from threatlens.core.models.alert import (
    MAX_RISK,
    TERMINAL_STATUSES,
    Alert,
    AlertStatus,
    ScoreContribution,
)
from threatlens.core.models.common import (
    SEVERITY_BANDS,
    Confidence,
    FieldIssue,
    Frozen,
    Observation,
    Pid,
    Port,
    Severity,
    severity_for_score,
)
from threatlens.core.models.detection import (
    MAX_RULE_SCORE,
    DetectionResult,
    Evidence,
    NetworkContext,
    RuleCategory,
    RuleMetadata,
)
from threatlens.core.models.events import (
    EVENT_SCHEMA_VERSION,
    INVENTORY_EVENT_TYPES,
    EventType,
    SecurityEvent,
)
from threatlens.core.models.health import (
    STATUS_SCHEMA_VERSION,
    BusStats,
    ComponentHealth,
    ComponentStatus,
    EngineState,
    EngineStats,
    EngineStatus,
)
from threatlens.core.models.network import (
    AddressFamily,
    AddressScope,
    Attribution,
    ConnectionState,
    CorrelatedConnection,
    Direction,
    NetworkConnection,
    NetworkSnapshot,
    TransportProtocol,
)
from threatlens.core.models.persistence import (
    PersistenceItem,
    PersistenceKind,
    PersistenceSnapshot,
)
from threatlens.core.models.process import (
    Architecture,
    IntegrityLevel,
    ProcessInfo,
    ProcessNode,
    ProcessSnapshot,
    SignatureInfo,
    SignatureSource,
    SignatureStatus,
    make_process_key,
)

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "INVENTORY_EVENT_TYPES",
    "MAX_RISK",
    "MAX_RULE_SCORE",
    "SEVERITY_BANDS",
    "STATUS_SCHEMA_VERSION",
    "TERMINAL_STATUSES",
    "ActionOutcome",
    "ActionType",
    "AddressFamily",
    "AddressScope",
    "Alert",
    "AlertStatus",
    "Architecture",
    "Attribution",
    "BusStats",
    "ComponentHealth",
    "ComponentStatus",
    "Confidence",
    "ConnectionState",
    "CorrelatedConnection",
    "DetectionResult",
    "Direction",
    "EngineState",
    "EngineStats",
    "EngineStatus",
    "EventType",
    "Evidence",
    "FieldIssue",
    "Frozen",
    "IntegrityLevel",
    "NetworkConnection",
    "NetworkContext",
    "NetworkSnapshot",
    "Observation",
    "PersistenceItem",
    "PersistenceKind",
    "PersistenceSnapshot",
    "Pid",
    "Port",
    "ProcessInfo",
    "ProcessNode",
    "ProcessSnapshot",
    "ResponseAction",
    "RuleCategory",
    "RuleMetadata",
    "ScoreContribution",
    "SecurityEvent",
    "Severity",
    "SignatureInfo",
    "SignatureSource",
    "SignatureStatus",
    "TransportProtocol",
    "make_process_key",
    "severity_for_score",
]
