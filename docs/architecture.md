# ThreatLens Architecture

> **See what your Windows system is doing. Detect what shouldn't be happening. Respond safely.**

This document is the engineering design for ThreatLens V1. It is written *before* most of the
code, and every phase is expected to conform to it (or update it deliberately).

Contents

1. [Requirements analysis](#1-requirements-analysis)
2. [Windows-specific technical constraints](#2-windows-specific-technical-constraints)
3. [APIs and libraries](#3-apis-and-libraries)
4. [Privilege matrix](#4-privilege-matrix)
5. [Architecture](#5-architecture)
6. [Project tree](#6-project-tree)
7. [Core data models](#7-core-data-models)
8. [Module interfaces](#8-module-interfaces)
9. [Event schema](#9-event-schema)
10. [Detection rule schema](#10-detection-rule-schema)
11. [Risk-scoring model](#11-risk-scoring-model)
12. [SQLite schema](#12-sqlite-schema)
13. [CLI command structure](#13-cli-command-structure)
14. [Testing strategy](#14-testing-strategy)
15. [Implementation phases](#15-implementation-phases)

---

## 1. Requirements analysis

ThreatLens is a **local-first, transparent, defensive** host monitor. The requirements reduce to
five capabilities, in priority order:

| # | Capability | Why it matters |
|---|------------|----------------|
| 1 | **Visibility**: processes, lineage, sockets, persistence, events | You cannot defend what you cannot see. |
| 2 | **Correlation**: process ↔ network ↔ lineage ↔ time | Individual observations are rarely suspicious; *combinations* are. |
| 3 | **Explainable detection**: rules that emit evidence, scored conservatively | Unknown ≠ malicious. Unsigned ≠ malware. Every score must be explainable. |
| 4 | **Human-in-the-loop response**: suspend / resume / terminate / firewall | Automated killing of processes on a personal machine causes more harm than good. |
| 5 | **Auditability**: SQLite record of what was seen, decided and done | A security tool must itself be accountable. |

Non-goals for V1 (explicit): kernel drivers, ETW real-time sessions, TLS interception, packet
capture, cloud telemetry, auto-remediation, YARA/Sigma, remote management.

Hard constraints that shape the design:

* **Polling is the V1 foundation.** Event-driven process creation on Windows needs either admin
  (WMI `Win32_ProcessStartTrace`, ETW kernel provider, Security log 4688) or a driver. A
  standard-user tool must therefore poll, and must be honest that polling misses short-lived
  processes. Event-driven sources are *additive* enrichers when available.
* **Every OS call can fail.** Access denied, process exited, PID reused, handle invalid. Partial
  data is the normal case, not the exception, so models carry *why* a field is missing.
* **One broken collector must never stop the engine.**

---

## 2. Windows-specific technical constraints

These are the realities of Windows that the code must respect. `docs/windows-internals.md`
explains each in depth.

### 2.1 Processes

| Constraint | Consequence for ThreatLens |
|------------|-----------------------------|
| **PIDs are reused quickly.** Windows recycles PIDs (multiples of 4) aggressively. | A PID alone is never an identity. We use **`process_key = "<pid>:<create_time_ms>"`**. |
| **Parent PID is a creation-time snapshot**, not a live link (`InheritedFromUniqueProcessId`). The parent may exit and its PID may be reused by an unrelated process. | The tree builder validates `parent.create_time <= child.create_time`; otherwise the child is marked *orphaned* rather than attached to the wrong parent. |
| **Parent PID can be spoofed** (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`). | Lineage from polling is *observed-as-reported*; documented as a limitation. ETW/Sysmon (future) record the true creator. |
| **Protected processes (PPL)** — `csrss`, `smss`, `lsass` (with RunAsPPL), Defender — deny most access even to Administrators. | Fields such as `exe`, `cmdline`, `username` come back as *access denied*. We show "unavailable (access denied)", never a guess. |
| **Standard users cannot read other users' / SYSTEM processes' command line or token.** | Degraded, clearly labelled output when not elevated. |
| **CPU% needs two samples.** | The collector keeps each process's previous CPU-time sample keyed by `process_key`; the first sighting reports `cpu_percent = null` ("not yet sampled") rather than a fake 0. |
| **Polling misses processes that live shorter than the interval.** | Documented. Security log 4688 / Sysmon event 1 fill the gap when available (Phase 4+). |
| **WOW64 / ARM64 emulation** changes what "architecture" means. | `IsWow64Process2` reports x86-on-x64; x64-on-ARM64 emulation is not distinguishable via that API (documented). |

### 2.2 Network

| Constraint | Consequence |
|------------|-------------|
| `GetExtendedTcpTable` / `GetExtendedUdpTable` expose the **owning PID** per socket. | This is the basis of PID ↔ network correlation. It works without admin. |
| The table is a **point-in-time snapshot**. | Connections shorter than the poll interval are missed; "repeated attempts" rules must work on sampled data. |
| **UDP has no remote endpoint** in the table (connectionless). | UDP rows show local bindings only. |
| **Kernel-mode sockets are owned by PID 4 (System)** — SMB, `http.sys` listeners. | A listener owned by System may really belong to IIS/WinRM/etc. Documented; rules treat PID 4 specially. |
| **`svchost.exe` hosts many services.** | Socket → service attribution needs the service tag (`GetOwnerModuleFromTcpEntry`) — future enhancement. |
| Owning PID may exit between table read and process lookup. | Correlation marks the connection *unattributed* rather than crashing. |

### 2.3 DNS

There is **no standard-user, per-process DNS API**. Options, in order of preference:

1. `Microsoft-Windows-DNS-Client/Operational` event log (events 3006/3008/3020) — includes the
   process ID in the event's `System` block, but the channel is **disabled by default** and
   enabling it requires admin.
2. ETW provider `Microsoft-Windows-DNS-Client` — real-time sessions require admin (future).
3. `DnsGetCacheDataTable` — undocumented, no process attribution. **Not used.**

ThreatLens will never intercept, redirect or decrypt DNS/TLS traffic.

### 2.4 Event logs

* `Security` log requires **admin** (or membership of *Event Log Readers*).
* 4688 (process creation) additionally requires the *Audit Process Creation* policy, and
  command-line capture requires a separate policy setting.
* `System` (7045 service installed) and `Microsoft-Windows-TaskScheduler/Operational`
  (106 task registered) are readable by standard users.

### 2.5 Persistence

* `HKCU\...\Run`, `HKLM\...\Run`, `RunOnce`, Startup folders: readable by standard users.
* Scheduled tasks via the Task Scheduler COM API: standard users see only a subset.
* Services via `EnumServicesStatusEx`: readable; some service config requires admin.

### 2.6 Response actions

* Suspend/resume (`NtSuspendProcess`/`NtResumeProcess`) needs `PROCESS_SUSPEND_RESUME`.
  Terminate needs `PROCESS_TERMINATE`. Standard users can act only on their own processes at the
  same or lower integrity. PPL processes cannot be suspended or terminated even by admins.
* Firewall rule creation (`INetFwPolicy2`) **requires admin**.

### 2.7 Signatures

* Most in-box Windows binaries are **catalog-signed**, not embedded-signed. Checking only the
  embedded signature would label `notepad.exe` as unsigned — a classic false positive. We check
  embedded *then* catalog.
* Revocation checks hit the network. V1 is offline-first: **revocation is not checked** by
  default (documented, configurable later).
* A signer name from an *invalid* signature is attacker-controlled text; it is only displayed for
  VALID signatures.

---

## 3. APIs and libraries

| Library | Used for | Why this choice |
|---------|----------|-----------------|
| **ctypes** (stdlib) | **Process collection** (`NtQuerySystemInformation`, `QueryFullProcessImageNameW`, `NtQueryInformationProcess`, token queries, `IsWow64Process2`), elevation, `WinVerifyTrust` + catalog APIs | Zero dependency, each Win32 call explicit and readable. Every foreign function declares `argtypes`/`restype` (essential for 64-bit handles). |
| **psutil** | Socket tables with owning PID (Phase 2), services, system CPU/RAM | Mature wrapper around `GetExtendedTcpTable` etc. **Not used for per-process collection** — see the measurement below. |

> **Measured design change (Phase 1).** psutil's per-process getters on Windows re-enumerate the
> whole system on each call (`ppid()` walks a Toolhelp snapshot; `num_threads`, `status`,
> `create_time` fall back to `NtQuerySystemInformation`). For 273 processes a steady-state
> snapshot took **~2.4 s**. One bulk `NtQuerySystemInformation(SystemProcessInformation)` call
> plus one handle per *new* process takes **~54 ms cold / ~9 ms steady** on the same machine.
| **pywin32** *(Phase 4+)* | Event log (`EvtQuery`/`EvtSubscribe`), Task Scheduler COM, Firewall COM (`HNetCfg.FwPolicy2`) | COM from raw ctypes is error-prone; pywin32 is the standard. Added only when first used. |
| **watchdog** *(Phase 12)* | File monitor (`ReadDirectoryChangesW`) | Handles the overlapped-I/O loop and buffer handling. |
| **rich** | Tables, trees, panels, live dashboard | Best-in-class terminal rendering; no curses on Windows. |
| **pydantic v2** | Domain models + config validation | Validation of untrusted config, immutable models, stable JSON schemas for the future API. The Rust core keeps per-object cost in microseconds. |
| **argparse** (stdlib) | CLI | Nested subcommands without extra dependencies; friendly to PyInstaller. |
| **sqlite3** (stdlib) | Storage | Local, transactional, WAL mode for crash safety. |
| **tomllib** (stdlib) | Reading config | TOML without a dependency. |
| pytest, mypy, ruff | Dev only | Tests, static typing, linting. |

**Rejected:** `os.system`/`shell=True` (injection), WMI polling for processes (heavier than
`NtQuerySystemInformation` and still polling), PowerShell `Get-AuthenticodeSignature` (spawns a
process per file; slow), raw packet capture (needs a driver, out of scope).

---

## 4. Privilege matrix

| Capability | Standard user | Administrator | Notes |
|------------|:---:|:---:|-------|
| Enumerate all PIDs, names, PPIDs, create times | ✅ | ✅ | `NtQuerySystemInformation` |
| Exe path of other users' processes | ⚠️ most | ⚠️ most | PPL and System/Idle always denied |
| Command line / username of SYSTEM & other users' processes | ❌ | ✅ (not PPL) | |
| Integrity level of other users' processes | ⚠️ partial | ✅ (not PPL) | |
| SHA256 / signature of an executable | ✅ if file readable | ✅ | Some `System32` files are readable by all |
| TCP/UDP tables with owning PID | ✅ | ✅ | |
| DNS client event log | ❌ enable / ✅ read if enabled | ✅ | Channel disabled by default |
| Security event log (4624, 4688, 4672…) | ❌ | ✅ | |
| System log (7045), TaskScheduler log | ✅ | ✅ | |
| Run keys, Startup folders | ✅ | ✅ | |
| All scheduled tasks | ⚠️ subset | ✅ | |
| Suspend/resume/terminate own processes | ✅ | ✅ | |
| Suspend/resume/terminate other users' / elevated processes | ❌ | ✅ (not PPL) | |
| Create/remove firewall rules | ❌ | ✅ | |

ThreatLens **never self-elevates**. It detects elevation, reports reduced functionality, and
continues.

---

## 5. Architecture

### 5.1 Layered pipeline

```
                          ┌───────────────────── cli.py (composition root) ─────────────────────┐
                          │  builds Config → Collectors → Monitors → Engine → UI / Storage     │
                          └──────────────────────────────────────────────────────────────────────┘

 WINDOWS HOST
     │  (Win32 / NT APIs via psutil, ctypes, pywin32)
     ▼
┌────────────┐   snapshots    ┌────────────┐   SecurityEvent   ┌───────────┐
│ collectors │ ─────────────▶ │  monitors  │ ────────────────▶ │ event_bus │ (bounded queue)
│ (stateless │                │ (diff +    │                   └─────┬─────┘
│  OS reads) │                │  schedule) │                         │ dispatch thread
└────────────┘                └────────────┘                         ▼
                                                             ┌──────────────┐
                                                             │    state     │ current processes,
                                                             │ (in-memory)  │ connections, recent events
                                                             └──────┬───────┘
                                                                    ▼
                      ┌──────────────┐    DetectionResult    ┌──────────────┐
                      │ correlation  │ ◀──────────────────── │  detection   │  rules(event, state)
                      │ tree/net/time│ ────────────────────▶ │   engine     │
                      └──────────────┘    context            └──────┬───────┘
                                                                    ▼
                                                             ┌──────────────┐
                                                             │   scoring    │ → Alert
                                                             └──────┬───────┘
                                              ┌─────────────────────┼──────────────────────┐
                                              ▼                     ▼                      ▼
                                        ┌──────────┐          ┌──────────┐           ┌──────────┐
                                        │ storage  │          │    ui    │           │ response │
                                        │ (SQLite) │          │  (rich)  │           │ (guarded)│
                                        └──────────┘          └──────────┘           └──────────┘
```

### 5.2 Architectural decisions

| Decision | Rationale |
|----------|-----------|
| **Collectors are stateless and do no I/O besides reading the OS.** | Trivially mockable; can be called from CLI one-shot commands *and* from the live engine. |
| **Monitors own scheduling and diffing** (snapshot N vs N−1 → events). | Separates "what exists" from "what changed". The differ is a pure function, unit-testable without Windows. |
| **Threads, not asyncio.** | psutil, ctypes and pywin32 calls are blocking. asyncio would push every call into `to_thread` anyway. A few worker threads plus one bounded queue is simpler and easier to reason about. |
| **Bounded event queue, drop-oldest with a counter.** | Under an event storm memory stays bounded; the drop counter is surfaced in `status` so loss is visible, never silent. |
| **Single SQLite writer thread**, WAL mode. | SQLite allows one writer; funnelling writes avoids `database is locked` and makes Ctrl+C flush deterministic. |
| **Detection rules are small classes with a declared `event_types` filter.** | Plugin-like: add a file, register, test in isolation with a fake `StateView`. |
| **Rules never act; the response layer never detects.** | Prevents "detection → automatic kill" coupling. Response is only reachable from an explicit user command. |
| **UI consumes models only.** | Dashboard contains zero detection logic; a future REST API or GUI reuses the same engine. |
| **Process identity = `(pid, create_time)`.** | Defeats PID reuse bugs, which are a real source of wrong-process kills in naive tools. |
| **Models record `unavailable` fields with reasons.** | Distinguishes "empty" from "access denied" from "process exited". Honest output is a security property. |
| **Redaction at collection time.** | Secrets in command lines (`--password=…`) never enter the bus, database or logs. Detection does not need secret values. |
| **Dependency injection via constructor parameters** (clock, process source, caches). | Temporal rules and collectors are testable with fake clocks and fake processes. |
| **Composition root is `cli.py`.** | Only one place knows how the object graph is wired; everything else receives dependencies. |

### 5.3 Dependency rules

```
cli ──▶ ui, core, collectors, monitors, detection, correlation, response, storage, config
ui ──▶ core.models, correlation (result types), core.diagnostics (result types)
core.engine ──▶ monitors, collectors, core.state, core.event_bus, core.scheduler
monitors ──▶ collectors, correlation, core.models
detection ──▶ core.models, core.interfaces, correlation; detection.scan ──▶ core.state
correlation ──▶ core.models
response ──▶ core.models, security, storage (audit)
storage ──▶ core.models
collectors ──▶ core.models, security, utils
security ──▶ core.models (enums/result models only), utils
core.models ──▶ utils.time
utils.networking ──▶ core.models (enums only)
utils (all other modules) ──▶ stdlib, ctypes, errors
```

No module imports `ui` or `cli` except `cli`. Rules never import `response`.

### 5.4 Runtime threads (as built in Phase 4)

| Thread | Work | Failure isolation |
|--------|------|-------------------|
| `threatlens-process_monitor` | Poll processes → apply to state → publish lifecycle events | Exceptions caught by its `TaskRunner`: `DEGRADED` after 1 failure, `UNAVAILABLE` after 3, exponential backoff to `engine.max_backoff_seconds`. |
| `threatlens-network_monitor` | Poll sockets → correlate (resolving unseen PIDs on demand) → publish | Same, independently of the process monitor. |
| `threatlens-status_writer` | Atomically write `engine-status.json` | Same; a write failure never affects collection. |
| `threatlens-watchdog` | Mark any run exceeding `collectors.collector_timeout_seconds` as `TIMED_OUT` | Threads cannot be killed safely; the hung component is reported while others continue. |
| `threatlens-enrichment` | SHA256 + signature in Windows background mode; new processes before inventory | Per-item exception isolation; bounded queue with drop counter. |
| `threatlens-dispatcher` | Drain the bounded bus: state history → enrichment requests → stream → detection | Per-handler isolation; detection disables a rule after 10 consecutive failures. |
| main | CLI; sleeps in 250 ms slices so Ctrl+C is delivered promptly | `KeyboardInterrupt` → ordered shutdown. |

Startup: bus + enrichment start → first process poll and first network poll run synchronously
(in that order, so inventory sockets are attributable) → scheduler threads start.

Shutdown order: stop scheduler threads → stop enrichment → drain the bus → write final status
(`STOPPED`) → release the single-instance lock. Storage flushing joins this sequence in Phase 7.

---

## 6. Project tree

```
ThreatLens/                           (repository root)
├── pyproject.toml
├── README.md  LICENSE  CONTRIBUTING.md  SECURITY.md  .gitignore  .env.example
├── src/threatlens/
│   ├── __init__.py  __main__.py
│   ├── cli.py                        composition root + argparse commands
│   ├── config.py                     pydantic config, TOML loading, defaults
│   ├── logging_config.py             key=value structured logging, log-injection safe
│   ├── errors.py                     exception hierarchy + CLI exit codes          (added)
│   ├── core/
│   │   ├── models/                   package: common, process, network, events, health, detection
│   │   ├── interfaces.py             StateView, DetectionRule protocols           (added)
│   │   ├── engine.py  event_bus.py  scheduler.py  state.py        (Phase 4)
│   │   ├── enrichment.py             background hashing/signatures                (added, Phase 4)
│   │   ├── status_file.py            atomic status file + single-instance lock    (added, Phase 4)
│   │   └── diagnostics.py            collector self-test for `status`             (added, Phase 4)
│   ├── collectors/
│   │   ├── process_collector.py      (Phase 1)
│   │   ├── network_collector.py      (Phase 2)
│   │   ├── dns_collector.py  eventlog_collector.py  system_collector.py            (later)
│   ├── monitors/
│   │   ├── process_monitor.py        inventory + snapshot diffing
│   │   ├── network_monitor.py        socket diffing (Phase 4)
│   │   └── eventlog_monitor.py  file_monitor.py  persistence_monitor.py            (later)
│   ├── correlation/
│   │   ├── process_tree.py           (Phase 1)
│   │   └── process_network.py        (Phase 3)
│   ├── detection/                    (Phase 5)
│   │   ├── engine.py  scan.py  settings.py  paths.py  catalog.py
│   │   └── rules/  base.py  origin.py  execution.py  network.py
│   ├── response/   process_control.py firewall_control.py response_manager.py      (later)
│   ├── security/
│   │   ├── hashing.py  signatures.py  privileges.py  redaction.py (added)
│   ├── storage/    database.py repositories.py migrations.py                       (later)
│   ├── ui/         process_views  network_views  detection_views  event_stream  status_view
│   │               json_output  formatting  colors
│   └── utils/      windows.py ntapi.py iphlpapi.py networking.py time.py lru.py
├── tests/
│   ├── conftest.py
│   ├── unit/  integration/  fixtures/
├── docs/  architecture.md detection-rules.md windows-internals.md troubleshooting.md
└── scripts/  lab/ (benign test-lab scenarios)
```

Deviations from the suggested tree, and why:

* **`core/interfaces.py`** — Protocols live in one place so layers depend on abstractions, not on
  each other's concrete classes.
* **`errors.py`** — one exception hierarchy maps cleanly to CLI exit codes.
* **`security/redaction.py`** — command-line secret redaction is a security control and deserves
  its own tested module.
* **`utils/lru.py`** — a thread-safe bounded cache shared by hashing and signature verification.
* **`detection/rules/` as a package** (Phase 5) — one module per rule family keeps rules small.
* **`utils/ntapi.py`, `utils/iphlpapi.py`** — raw Windows structures kept apart from the collectors
  that interpret them, so structure layouts are testable in isolation.
* **`core/models/` as a package** — one module per domain instead of one growing file.
* **`correlation/event_correlation.py` deferred** — per-process event history lives in
  `core/state.py`; behaviour chains are built when combined scoring arrives (Phase 6).

---

## 7. Core data models

All models are immutable pydantic v2 models (`frozen=True`, `extra="forbid"`) defined in the
`core/models/` package and re-exported from `threatlens.core.models`. Timestamps are
timezone-aware UTC. JSON uses ISO-8601.

> As built (Phases 1–5), a few names differ from this original plan: `Protocol` is
> `TransportProtocol` (avoids clashing with `typing.Protocol`); `RemoteScope` is `AddressScope`
> (applies to local addresses too, adds `RESERVED`); `Direction` adds `BOUND` for UDP;
> `ConnectionState` uses `SYN_RECEIVED`, `FIN_WAIT_1`, `FIN_WAIT_2` and adds `CLOSED`;
> `SignatureSource` adds `PACKAGE`; `FieldIssue` adds `TOO_LARGE`; `ProcessInfo` reports
> `working_set`, `private_bytes` and `handle_count`; `NetworkConnection` carries the kernel
> `created_at` and `owner_module`; attribution lives in `CorrelatedConnection` (with an
> `Attribution` enum) rather than on the socket itself. `ComponentStatus` adds `STARTING`,
> `TIMED_OUT` and `DISABLED`. The source code is authoritative.

### Enumerations

| Enum | Values |
|------|--------|
| `Severity` | `NORMAL`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `Confidence` | `LOW`, `MEDIUM`, `HIGH` |
| `Observation` | `OBSERVED` (seen directly), `INFERRED` (derived), `SUSPICIOUS` (analyst-grade judgement), `CONFIRMED` (user-confirmed) |
| `SignatureStatus` | `VALID`, `INVALID`, `UNSIGNED`, `UNKNOWN` |
| `SignatureSource` | `EMBEDDED`, `CATALOG`, `NONE` |
| `IntegrityLevel` | `UNTRUSTED`, `LOW`, `MEDIUM`, `HIGH`, `SYSTEM`, `UNKNOWN` |
| `Architecture` | `X86`, `X64`, `ARM64`, `ARM`, `UNKNOWN` |
| `FieldIssue` | `ACCESS_DENIED`, `PROCESS_EXITED`, `NOT_APPLICABLE`, `ERROR` |
| `Protocol` | `TCP`, `UDP` |
| `AddressFamily` | `IPV4`, `IPV6` |
| `ConnectionState` | `ESTABLISHED`, `LISTEN`, `SYN_SENT`, `SYN_RECV`, `FIN_WAIT1`, `FIN_WAIT2`, `CLOSE_WAIT`, `CLOSING`, `LAST_ACK`, `TIME_WAIT`, `DELETE_TCB`, `NONE` |
| `Direction` | `OUTBOUND`, `INBOUND`, `LISTENING`, `UNKNOWN` |
| `RemoteScope` | `LOOPBACK`, `PRIVATE`, `LINK_LOCAL`, `PUBLIC`, `MULTICAST`, `UNSPECIFIED` |
| `EventType` | see §9 |
| `AlertStatus` | `NEW`, `ACKNOWLEDGED`, `INVESTIGATING`, `RESOLVED`, `IGNORED` |
| `ActionType` | `SUSPEND_PROCESS`, `RESUME_PROCESS`, `TERMINATE_PROCESS`, `FIREWALL_BLOCK_IP`, `FIREWALL_BLOCK_PORT`, `FIREWALL_BLOCK_PROCESS`, `FIREWALL_UNBLOCK`, `ALLOWLIST_ADD`, `ALLOWLIST_REMOVE`, `ALERT_STATUS_CHANGE`, `BASELINE_CREATE` |
| `ActionOutcome` | `SUCCEEDED`, `FAILED`, `CANCELLED`, `DENIED_BY_POLICY` |

### Models

```text
SignatureInfo      status, source, signer (only when VALID), error_code, detail
ProcessInfo        process_key, pid, ppid, name, exe, cmdline, username, create_time,
                   cpu_percent, memory_rss, num_threads, session_id, integrity_level,
                   architecture, suspended, sha256, signature, unavailable{field: FieldIssue},
                   collected_at
ProcessNode        process (ProcessInfo), children [ProcessNode], parent_valid (bool)
NetworkConnection  protocol, family, local_address, local_port, remote_address, remote_port,
                   state, direction, remote_scope, pid, process_key, process_name, observed_at
SecurityEvent      schema_version, event_id, event_type, timestamp, source, observation,
                   process_key, pid, data{...}
Evidence           description, observation, field, value
DetectionResult    detection_id, rule_id, rule_name, category, timestamp, score, confidence,
                   evidence[], process_key, pid, event_ids[], mitre_techniques[]
NetworkContext     remote_address, remote_port, protocol, state, remote_scope
Alert              alert_id, created_at, updated_at, title, severity, confidence, risk_score,
                   status, process_key, pid, process_name, exe, network[], detections[],
                   rules_triggered[], score_breakdown[], recommended_actions[]
ResponseAction     action_id, timestamp, action_type, target, process_key, pid, reason,
                   requested_by, outcome, error, reverses_action_id
PersistenceItem    item_key, kind, location, name, command, executable, sha256, signature,
                   first_seen, last_seen
BaselineItem       kind, item_key, attributes{}, first_seen
ComponentHealth    name, status (OK/DEGRADED/UNAVAILABLE/STOPPED), last_success, last_error,
                   detail
```

*Phase 1 implements the process-related models concretely; the remaining models are added in the
phase that first produces them, so no model exists without a producer and a test.*

---

## 8. Module interfaces

Defined as `typing.Protocol` in `core/interfaces.py` (added incrementally per phase).

```python
class Clock(Protocol):
    def now(self) -> datetime: ...                     # UTC; fakeable for temporal rules

class SystemProcessSource(Protocol):                    # bulk enumeration (one syscall)
    def query(self) -> Sequence[SystemProcessEntry]: ...

class ProcessInspector(Protocol):                       # per-process static details
    def open(self, pid: int) -> ContextManager[ProcessDetailsReader]: ...   # one handle
    def image_path_by_pid(self, pid: int) -> str: ...   # handle-free fallback

class Collector(Protocol[T_co]):
    name: str
    def collect(self) -> T_co: ...                      # raises CollectorUnavailable on total failure

class Monitor(Protocol):
    name: str
    def poll(self) -> Sequence[SecurityEvent]: ...      # one tick: collect → diff → events
    def health(self) -> ComponentHealth: ...

class EventBus(Protocol):
    def publish(self, event: SecurityEvent) -> bool: ...   # False if dropped
    def subscribe(self, types: Collection[EventType], handler: Callable[[SecurityEvent], None]) -> None: ...

class StateView(Protocol):                              # read-only view rules receive (as built)
    def now(self) -> datetime: ...
    def process(self, process_key: str) -> ProcessInfo | None: ...       # running or recently exited
    def process_by_pid(self, pid: int) -> ProcessInfo | None: ...
    def parent_of(self, process: ProcessInfo) -> ProcessInfo | None: ...  # verified, incl. exited
    def ancestors(self, process: ProcessInfo, limit: int = 16) -> list[ProcessInfo]: ...
    def connections_of(self, process_key: str) -> list[CorrelatedConnection]: ...
    def events_for(self, process_key: str, within: timedelta | None = None) -> list[SecurityEvent]: ...
    # is_baselined / is_allowlisted join the protocol with baselines and allowlists (Phase 11).

class DetectionRule(Protocol):
    @property
    def meta(self) -> RuleMetadata: ...
    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None: ...

class ProcessController(Protocol):                      # response layer; fakeable
    def suspend(self, pid: int, expected_key: str) -> None: ...
    def resume(self, pid: int, expected_key: str) -> None: ...
    def terminate(self, pid: int, expected_key: str) -> None: ...
```

`expected_key` on response actions guarantees we act on the process the user *inspected*, not a
new process that inherited its PID in the meantime.

---

## 9. Event schema

Every observation that flows through the engine is a `SecurityEvent`:

```json
{
  "schema_version": 1,
  "event_id": "5b0d7c2e-3f0a-4a0e-9d7e-2a3c1c0f9e11",
  "event_type": "PROCESS_STARTED",
  "timestamp": "2026-09-15T11:32:04.123456Z",
  "source": "process_monitor",
  "observation": "OBSERVED",
  "process_key": "4832:1789471924123",
  "pid": 4832,
  "data": { "name": "unknown.exe", "ppid": 3920, "exe": "C:\\Users\\…\\Temp\\unknown.exe" }
}
```

| `event_type` | Source | `data` keys |
|--------------|--------|-------------|
| `PROCESS_DISCOVERED` / `PROCESS_STARTED` | process_monitor | name, ppid, parent_key, parent_name, exe, cmdline, username, integrity_level, session_id, create_time |
| `PROCESS_STOPPED` | process_monitor | name, exe, exited_after, exited_before, max_lifetime_seconds |
| `PROCESS_CHANGED` | process_monitor | name, changed: {suspended: [old, new]} |
| `PROCESS_ENRICHED` | enrichment | name, exe, sha256, signature_status, signature_source, signer, signature_detail |
| `CONNECTION_DISCOVERED` / `CONNECTION_OPENED` / `CONNECTION_CLOSED` | network_monitor | the flat connection record: pid, process, process_key, exe, attribution, protocol, family, local/remote address+port, state, direction, local/remote scope, created_at, owner_module, connection_key |
| `LISTENER_DISCOVERED` / `LISTENER_OPENED` / `LISTENER_CLOSED` | network_monitor | same record (UDP only for ports below 49152) |
| `DNS_QUERY` | dns_collector | query_name, query_type, status, addresses |
| `EVENTLOG_RECORD` | eventlog_monitor | channel, event_record_id, windows_event_id, provider, fields |
| `FILE_CREATED` / `FILE_MODIFIED` / `FILE_DELETED` | file_monitor | path, extension, size |
| `PERSISTENCE_ADDED` / `PERSISTENCE_REMOVED` / `PERSISTENCE_CHANGED` | persistence_monitor | kind, location, name, command, executable |
| `COLLECTOR_STATUS` | engine | component, status, previous_status, last_error, detail |

`DNS_QUERY`, `EVENTLOG_RECORD`, `FILE_*` and `PERSISTENCE_*` are added with their monitors.

Rules: `schema_version` bumps on any breaking change; fields are only ever *added* within a
version. `data` values are JSON primitives, lists or objects — never binary. Detections travel
on a separate typed channel (`DetectionEngine.subscribe`), not as bus events.

---

## 10. Detection rule schema

```python
class RuleMetadata(Frozen):       # as built
    rule_id: str                  # ^[A-Z]{2,8}-\d{3}$, e.g. PROC-001
    name: str
    description: str
    rationale: str                # why the behaviour is suspicious (shown by `rules show`, `inspect`)
    category: RuleCategory        # ORIGIN, SIGNATURE, LINEAGE, EXECUTION, MASQUERADE, NETWORK, PERSISTENCE, BASELINE
    event_types: tuple[EventType, ...]   # at least one
    base_score: int               # 1..60 — no single rule may exceed 60
    confidence: Confidence
    mitre_techniques: tuple[str, ...] = ()   # validated T#### / T####.###
    false_positives: tuple[str, ...]         # at least one documented benign cause
    recommendation: str           # what the user can do
    enabled_by_default: bool = True
    default_severity: Severity    # property: severity band of base_score alone
```

A result may score *below* its rule's `base_score` (e.g. SIG-001: tampered +45, untrusted +30,
expired-without-timestamp +10) but never above. `DetectionResult.evidence` has `min_length=1`, so
an evidence-less result cannot be constructed. Config supports `detection.disabled_rules` and
`detection.ignored_executables` (full paths); per-rule score overrides are deferred to scoring.

V1 rules (14): origin — `PROC-001`, `PROC-002`, `SIG-001`; masquerading — `PROC-005`, `PROC-008`;
lineage — `PROC-003`, `TREE-001`; execution — `PROC-006`, `PROC-007`; network — `PROC-004`,
`NET-001`, `NET-002`, `NET-003`, `NET-004`. `PERSIST-001/002` and `BASE-001` arrive with their
monitors. Full specifications are generated into `docs/detection-rules.md`.

---

## 11. Risk-scoring model

Goals: explainable, conservative, **not a blind sum**, and resistant to many weak signals adding
up to "CRITICAL".

**Step 1 — effective contribution.** Each triggered rule contributes once per entity (duplicate
firings of the same rule do not stack):

```
effective_i = base_score_i × confidence_weight_i × context_modifier_i
confidence_weight: HIGH 1.0 · MEDIUM 0.75 · LOW 0.5
context_modifier:  1.0 default · 0.5 if the exe is in a trusted path or baselined ·
                   0.0 if allowlisted for that rule
```

**Step 2 — noisy-OR combination** (diminishing returns; can never exceed 100):

```
combined = 100 × (1 − Π (1 − effective_i / 100))
```

**Step 3 — corroboration bonus.** Independent *categories* agreeing is much stronger evidence
than one category firing many ways:

```
bonus = min(15, 5 × (distinct_categories − 1))
risk  = min(100, round(combined + bonus))
```

**Step 4 — caps.**
* If every contributing rule is LOW confidence → cap at 39 (LOW).
* If only one category contributed → cap at 59 (MEDIUM).

**Worked example** (`suspicious.exe`):

| Rule | Base | Conf | Effective |
|------|-----:|------|----------:|
| PROC-001 temp path (ORIGIN) | 20 | HIGH | 20 |
| PROC-002 unsigned in user-writable (SIGNATURE) | 15 | HIGH | 15 |
| PROC-003 suspicious parent (LINEAGE) | 25 | MEDIUM | 18.75 |
| PROC-004 external conn 2 s after start (NETWORK) | 20 | MEDIUM | 15 |
| NET-003 unusual port (NETWORK) | 10 | LOW | 5 |

`combined = 100 × (1 − 0.80·0.85·0.8125·0.85·0.95) ≈ 55.4`, 4 categories → `+15` → **70 HIGH**.

The same process in `C:\Program Files\` signed by a valid publisher would trigger none of the
origin/signature rules, and a lone "unusual port" would score 5 → **NORMAL**.

**Severity bands:** 0–19 NORMAL · 20–39 LOW · 40–59 MEDIUM · 60–79 HIGH · 80–100 CRITICAL.

**Alert confidence:** HIGH if ≥2 HIGH-confidence rules across ≥2 categories; MEDIUM if ≥2 rules
or any HIGH-confidence rule; otherwise LOW.

An alert is raised when `risk ≥ alert_threshold` (default 40). Every alert stores its
`score_breakdown` so the UI can print `+20 temp path, +15 unsigned, …`.

---

## 12. SQLite schema

Conventions: timestamps are ISO-8601 UTC `TEXT` (lexicographically sortable), JSON columns are
`TEXT` validated on write, all queries are parameterized, `PRAGMA journal_mode=WAL`,
`foreign_keys=ON`, `busy_timeout=5000`, `synchronous=NORMAL`.

```sql
CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, description TEXT NOT NULL, applied_at TEXT NOT NULL);

CREATE TABLE processes (
  process_key TEXT PRIMARY KEY, pid INTEGER NOT NULL, ppid INTEGER, parent_key TEXT,
  name TEXT NOT NULL, exe TEXT, cmdline TEXT, username TEXT, create_time TEXT,
  integrity_level TEXT, session_id INTEGER, architecture TEXT,
  sha256 TEXT, signature_status TEXT, signer TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, exited_at TEXT);
CREATE INDEX ix_processes_pid ON processes(pid);
CREATE INDEX ix_processes_name ON processes(name);
CREATE INDEX ix_processes_sha256 ON processes(sha256);
CREATE INDEX ix_processes_first_seen ON processes(first_seen);

CREATE TABLE process_events (
  id INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, process_key TEXT NOT NULL,
  event_type TEXT NOT NULL, timestamp TEXT NOT NULL, pid INTEGER, data TEXT NOT NULL,
  FOREIGN KEY (process_key) REFERENCES processes(process_key));
CREATE INDEX ix_process_events_ts ON process_events(timestamp);
CREATE INDEX ix_process_events_key ON process_events(process_key);

CREATE TABLE network_connections (
  id INTEGER PRIMARY KEY, process_key TEXT, pid INTEGER, protocol TEXT NOT NULL, family TEXT NOT NULL,
  local_address TEXT NOT NULL, local_port INTEGER NOT NULL, remote_address TEXT, remote_port INTEGER,
  state TEXT NOT NULL, direction TEXT NOT NULL, remote_scope TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, closed_at TEXT);
CREATE INDEX ix_net_first_seen ON network_connections(first_seen);
CREATE INDEX ix_net_pid ON network_connections(pid);
CREATE INDEX ix_net_remote ON network_connections(remote_address);
CREATE INDEX ix_net_key ON network_connections(process_key);

CREATE TABLE security_events (
  id INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, schema_version INTEGER NOT NULL,
  event_type TEXT NOT NULL, timestamp TEXT NOT NULL, source TEXT NOT NULL, observation TEXT NOT NULL,
  process_key TEXT, pid INTEGER, data TEXT NOT NULL);
CREATE INDEX ix_sec_events_ts ON security_events(timestamp);
CREATE INDEX ix_sec_events_type ON security_events(event_type, timestamp);
CREATE INDEX ix_sec_events_pid ON security_events(pid);

CREATE TABLE alerts (
  alert_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, updated_at TEXT NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL, confidence TEXT NOT NULL, risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
  status TEXT NOT NULL, process_key TEXT, pid INTEGER, process_name TEXT, exe TEXT,
  network TEXT NOT NULL, score_breakdown TEXT NOT NULL, recommended_actions TEXT NOT NULL);
CREATE INDEX ix_alerts_created ON alerts(created_at);
CREATE INDEX ix_alerts_severity ON alerts(severity, created_at);
CREATE INDEX ix_alerts_status ON alerts(status);
CREATE INDEX ix_alerts_pid ON alerts(pid);

CREATE TABLE detections (
  id INTEGER PRIMARY KEY, detection_id TEXT NOT NULL UNIQUE, alert_id TEXT REFERENCES alerts(alert_id),
  rule_id TEXT NOT NULL, timestamp TEXT NOT NULL, process_key TEXT, pid INTEGER,
  score INTEGER NOT NULL, confidence TEXT NOT NULL, category TEXT NOT NULL,
  evidence TEXT NOT NULL, event_ids TEXT NOT NULL);
CREATE INDEX ix_detections_ts ON detections(timestamp);
CREATE INDEX ix_detections_rule ON detections(rule_id);
CREATE INDEX ix_detections_alert ON detections(alert_id);

CREATE TABLE persistence_items (
  id INTEGER PRIMARY KEY, item_key TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, location TEXT NOT NULL,
  name TEXT NOT NULL, command TEXT, executable TEXT, sha256 TEXT, signature_status TEXT,
  first_seen TEXT NOT NULL, last_seen TEXT NOT NULL, removed_at TEXT);
CREATE INDEX ix_persist_kind ON persistence_items(kind);

CREATE TABLE actions (                      -- audit log; never auto-deleted by default
  action_id TEXT PRIMARY KEY, timestamp TEXT NOT NULL, action_type TEXT NOT NULL,
  target TEXT NOT NULL, process_key TEXT, pid INTEGER, reason TEXT NOT NULL,
  requested_by TEXT NOT NULL, outcome TEXT NOT NULL, error TEXT,
  reverses_action_id TEXT REFERENCES actions(action_id), details TEXT NOT NULL);
CREATE INDEX ix_actions_ts ON actions(timestamp);

CREATE TABLE firewall_rules (
  rule_name TEXT PRIMARY KEY, action_id TEXT NOT NULL REFERENCES actions(action_id),
  target_type TEXT NOT NULL, target TEXT NOT NULL, created_at TEXT NOT NULL, removed_at TEXT);

CREATE TABLE baselines (
  baseline_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT,
  created_by TEXT NOT NULL, hostname TEXT NOT NULL, notes TEXT);
CREATE TABLE baseline_items (
  id INTEGER PRIMARY KEY, baseline_id TEXT NOT NULL REFERENCES baselines(baseline_id) ON DELETE CASCADE,
  kind TEXT NOT NULL, item_key TEXT NOT NULL, attributes TEXT NOT NULL,
  UNIQUE (baseline_id, kind, item_key));

CREATE TABLE allowlist_entries (
  id INTEGER PRIMARY KEY, match_type TEXT NOT NULL CHECK (match_type IN ('EXE_PATH','SHA256','SIGNER','SIGNER_AND_PATH')),
  value TEXT NOT NULL, rule_ids TEXT, reason TEXT NOT NULL, created_at TEXT NOT NULL,
  created_by TEXT NOT NULL, expires_at TEXT, UNIQUE (match_type, value, rule_ids));

CREATE TABLE configuration_history (
  id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, config_sha256 TEXT NOT NULL,
  source_path TEXT NOT NULL, content TEXT NOT NULL);
```

Retention: `security_events`, `process_events`, `network_connections`, `detections` older than
`retention.event_days` are deleted in batches; `alerts` follow `retention.alert_days`; `actions`
are kept unless `retention.action_days` is set. Migrations are numbered Python functions applied
in a transaction and recorded in `schema_migrations`.

---

## 13. CLI command structure

Global flags (accepted before *or* after the subcommand): `--json`, `-q/--quiet`,
`-v/--verbose`, `--config PATH`, `--no-color`, `--version`, `-h/--help`.

```
threatlens status [--no-self-test]                  engine + collector health, privileges, self-test
threatlens monitor [--interval S] [--duration S] [--events LIST] [--loopback]
                                                     live event + detection stream (Rich dashboard: Phase 9)
threatlens processes [--sort cpu|memory|pid|name] [--limit N] [--user U] [--name SUBSTR] [--verify]
threatlens process <PID>                            one process, enriched (hash, signature)
threatlens inspect <PID>                            process + lineage + network + detections + risk
threatlens tree [--pid PID] [--depth N]
threatlens network   [--protocol tcp|udp] [--state S] [--pid PID] [--external] [--listening]
threatlens connections [--protocol] [--pid PID] [--external] [--verify]   non-listening sockets grouped by process
threatlens alerts [--severity S] [--today] [--status S] [--limit N]
threatlens alerts set-status <ALERT_ID> <STATUS>
threatlens events [--type T] [--since DURATION] [--pid PID]
threatlens persistence [--kind K]
threatlens baseline create [--name N] [--expires-days D]
threatlens baseline compare [--baseline ID]
threatlens baseline list | show <ID> | delete <ID>
threatlens rules [list | show <RULE_ID>]
threatlens suspend <PID>  [--yes] [--force-protected]
threatlens resume <PID>
threatlens terminate <PID> [--yes] [--force-protected]
threatlens firewall list | block-ip <IP> | block-port <PORT> [--protocol] | block-process <PATH> | unblock <RULE_NAME>
threatlens allow exe <PATH> | sha256 <HASH> | signer <NAME> [--path PATH] [--rules R,..] [--expires-days D]
threatlens logs [--tail N] [--level L]
threatlens config path | show | validate | init [--force]
threatlens db cleanup | vacuum | info
```

Exit codes: `0` success · `1` runtime error · `2` usage error · `3` insufficient privileges ·
`4` target not found · `5` cancelled by user · `6` blocked by safety policy.

JSON output is an envelope with a stable schema name:

```json
{ "schema": "threatlens.processes", "schema_version": 1, "timestamp": "…", "processes": [ … ] }
```

---

## 14. Testing strategy

| Layer | Approach |
|-------|----------|
| **Unit** (`tests/unit`) | Pure logic with fakes: `FakeProcessHandle` mimicking psutil's API (including `AccessDenied`/`NoSuchProcess` on specific fields), fake clock, in-memory SQLite. Covers parsers, differ, tree building with PID reuse, redaction, scoring maths, rules, config validation, allowlist matching. |
| **Integration** (`tests/integration`, marker `integration`) | Real Windows APIs against processes the test itself spawns (a benign `python -c "sleep"` child): verify PID, PPID, exe, cmdline, integrity level; start/stop detection across two snapshots; hash of a file with known content; signature of a catalog-signed system DLL (VALID) and a freshly created file (UNSIGNED); later a loopback socket owned by a child process. No test depends on an external IP or internet access. |
| **Lab** (`scripts/lab`) | Manual, benign scenarios from the spec (HTTP server on 8000, outbound loopback connection, parent→cmd→child chain, disposable Startup-folder entry with cleanup). |
| **Static** | `mypy --strict` on `src/`, `ruff check`. |

Tests that need admin are marked `requires_admin` and skipped with a reason when not elevated.

---

## 15. Implementation phases

| Phase | Scope | Exit criteria |
|------:|-------|---------------|
| **1** ✅ | Scaffolding, config, logging, core process models, Windows helpers (integrity/session/arch/version/elevation), hashing + cache, signature verification (embedded + catalog + MSIX awareness), redaction, **process collector**, snapshot differ, process tree, CLI `processes` / `process` / `tree` / `config` | Tests + mypy + ruff pass; commands run as standard user |
| **2** ✅ | Network collector (TCP/UDP, v4/v6, kernel socket timestamps, service owner, scope classification) + `network` | Loopback socket from spawned child is attributed to its PID |
| **3** ✅ | Process ↔ network correlation with PID-reuse rejection, `connections`, `inspect` | Connection → process → lineage chain rendered |
| **4** ✅ | Event bus, scheduler + watchdog, state, monitors, background enrichment, status file + lock, graceful shutdown, `monitor` (event stream), `status` | Engine survives an injected failing collector |
| **5** ✅ | Detection engine + 14 rules + `rules`; detections in `monitor` and `inspect` | Each rule has positive and negative tests |
| **6** ✅ | Risk scoring (noisy-OR + corroboration + caps) + alerts | Worked example in §11 reproduced by test |
| **7** ✅ | SQLite storage (WAL), migrations, batched writer, retention, `events` / `alerts` / `logs` / `db` | Crash-safe flush + checkpoint on Ctrl+C |
| **8** ✅ | JSON envelopes on every command; `--help` everywhere | Stable `schema`/`schema_version` |
| **9** ✅ | Live btop-style dashboard (`monitor`, the default view) with key controls | Renders < ~9 ms/frame; no crash on empty state |
| **10** ✅ | Response: suspend/resume/terminate + protected-process layer + audit; firewall via `netsh` (admin) | PID-reuse guard tested against a real child |
| **11** ✅ | Baseline create/compare/expiry + allowlist (path/sha256/signer) | Baseline diff reports new process / listener / persistence |
| **12** ✅ | Persistence collector + monitor + PERSIST rules; event-driven file monitor + FILE-001 | Real HKCU Run-key add and Temp-drop detected in tests. Event log & DNS deferred (see below) |
| **13** ✅ | Test hardening, benign lab scenarios | Full suite green (unit + Windows integration) |
| **14** ✅ | Packaging: `pyinstaller ThreatLens.spec` → `dist/ThreatLens.exe`; no-arg launch opens the dashboard | Single-file console exe |

**Deferred from Phase 12 (documented, not silently dropped).** Event-log ingestion (Security 4688
needs admin *and* audit policy; the DNS-Client operational channel is disabled by default and
enabling it needs admin) and per-process DNS are gated behind Administrator rights and machine
policy, so they add little for the default standard-user run and are left as clearly-scoped
roadmap items (§55) rather than half-working collectors. The event schema (`DNS_QUERY`,
`EVENTLOG_RECORD`) already reserves their shapes.
