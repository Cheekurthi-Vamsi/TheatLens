# Windows Internals Notes

This document explains the Windows mechanisms WinSentinel relies on. Each section answers the
project's engineering questions: *which API, why, what permissions, what limitations, what
happens on failure, and what alternatives exist.* Sections are added as phases land.

---

## Processes (Phase 1)

### 1. Enumerating every process in one call

**API:** `ntdll!NtQuerySystemInformation(SystemProcessInformation = 5, …)`

The kernel writes a buffer containing a linked list of `SYSTEM_PROCESS_INFORMATION` records.
Each record is followed by `NumberOfThreads` × `SYSTEM_THREAD_INFORMATION` records, and
`NextEntryOffset` points to the next process (0 terminates the list).

```
┌──────────────────────── buffer ───────────────────────────┐
│ SPI(pid 0) │ STI │ STI │ … │ SPI(pid 4) │ STI │ … │ SPI … │
└─────┬──────────────────────────▲─────────────────────────────┘
      └── NextEntryOffset ───────┘
```

| Field used | Meaning |
|------------|---------|
| `UniqueProcessId` | PID |
| `InheritedFromUniqueProcessId` | PID of the creator *at creation time* |
| `CreateTime` | 100-ns intervals since 1601-01-01 UTC (FILETIME) |
| `ImageName` | `UNICODE_STRING` — file name only, points *inside* the buffer |
| `SessionId` | Terminal Services session (0 = services) |
| `UserTime + KernelTime` | cumulative CPU time → CPU% from deltas |
| `WorkingSetSize`, `PrivatePageCount` | physical memory, committed private memory |
| thread `ThreadState` / `WaitReason` | all threads `Waiting(5)` for `Suspended(5)` ⇒ process is suspended |

* **Why:** one system call returns what psutil needs dozens of calls per process to obtain.
* **Permissions:** none — any user sees all processes, including protected ones.
* **Limitations:** partially documented (`winternl.h` marks many fields reserved) but the x64 layout
  has been stable since Vista; sizes are asserted in `tests/integration`. Snapshot semantics:
  short-lived processes between polls are missed.
* **On failure:** `STATUS_INFO_LENGTH_MISMATCH` → grow buffer and retry (bounded at 256 MB). Any
  other NTSTATUS → `CollectorUnavailableError`.
* **Alternatives:** `CreateToolhelp32Snapshot` (no memory/CPU), `EnumProcesses` (PIDs only), WMI
  (slow), ETW kernel provider / Sysmon (event-driven, admin).

**CPU%.** `(ΔCPU-time) / (Δwall-time × logical CPUs) × 100`, the same normalisation Task Manager
uses. The first sighting of a process has no previous sample, so its CPU is reported as `null`
("not yet sampled") rather than a misleading `0`.

**Suspended.** Store/UWP apps that Windows has frozen in the background (e.g.
`SystemSettings.exe`) legitimately show as suspended.

### 2. Static details from one handle

**API:** `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)`, then on that handle:

| Field | API |
|-------|-----|
| exe path | `QueryFullProcessImageNameW` |
| command line | `NtQueryInformationProcess(ProcessCommandLineInformation = 60)` → `CommandLineToArgvW` |
| user | `OpenProcessToken(TOKEN_QUERY)` → `GetTokenInformation(TokenUser)` → `LookupAccountSidW` |
| integrity | `GetTokenInformation(TokenIntegrityLevel)` → last sub-authority (RID) of the label SID |
| architecture | `IsWow64Process2` |

`PROCESS_QUERY_LIMITED_INFORMATION` (Vista+) is the least-privileged right that permits these
queries; many processes grant it while denying the older `PROCESS_QUERY_INFORMATION`.

These fields cannot change during a process's lifetime, so they are read **once per process
identity** and cached.

* **Permissions:** a standard user is denied the handle for SYSTEM and other users' processes (on a
  typical desktop about half of all processes). An administrator can open all non-protected
  processes. Protected Process Light (PPL) — `csrss.exe`, `smss.exe`, `lsass.exe` with RunAsPPL,
  Defender — stays inaccessible even to administrators.
* **On failure:** each field records a `FieldIssue` (`ACCESS_DENIED`, `PROCESS_EXITED`, …) and the
  UI shows `<access denied>` rather than a blank or a guess.

**Command line caveat.** Windows passes a process a *single string*, stored in its PEB. The
process can overwrite it after start (an anti-forensics trick). WinSentinel reads it at first
sighting — as early as polling permits.

**Integrity levels.** RIDs: `0x0000` untrusted, `0x1000` low (browser sandboxes), `0x2000` medium
(normal apps), `0x2100` medium-plus (UIAccess), `0x3000` high (elevated), `0x4000` system.
Seeing `UNTRUSTED` on Chrome/Edge renderer processes is expected: that is their sandbox.

### 3. Exe path without a handle

**API:** `NtQuerySystemInformation(SystemProcessIdInformation = 88)`

When `OpenProcess` is denied, the kernel will still return the image path for a PID, in NT device
form (`\Device\HarddiskVolume3\Windows\System32\lsass.exe`). `QueryDosDeviceW` on each drive letter
maps device names back to `C:`. Because the kernel reads this from the process object's image
file, user-mode code in the target cannot tamper with it. Result on a test machine as a standard
user: exe paths for 270 of 276 processes (the rest are file-less: *Registry*, *Memory
Compression*, *vmmem*, *Secure System*, Idle, System).

### 4. PIDs, reuse and parent verification

Windows recycles PIDs quickly. WinSentinel therefore identifies a process by
**`process_key = "<pid>:<creation-time-ms>"`**.

The parent PID is only a creation-time record. If the parent exits, its PID may be reassigned to
an unrelated process. The tree builder accepts a parent only if
`parent.create_time <= child.create_time`; otherwise the child is shown as a root with an
explanation (`parent PID 900 has exited; that PID now belongs to a newer, unrelated process`).

A parent PID can also be *spoofed* at creation with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`.
Polling cannot detect that; ETW (`Microsoft-Windows-Kernel-Process`) and Sysmon event 1 record the
real creator and are on the roadmap.

### 5. Pseudo processes

| PID | Name | Notes |
|----:|------|-------|
| 0 | System Idle Process | Its "CPU usage" is idle capacity. Never treated as a parent. |
| 4 | System | Kernel threads; owns kernel-mode sockets (SMB, http.sys). |
| varies | Registry, Memory Compression, Secure System, vmmem* | Minimal processes with no image file or PEB. |

---

## Signatures (Phase 1)

**API:** `wintrust!WinVerifyTrust` with `WINTRUST_ACTION_GENERIC_VERIFY_V2`.

1. **Embedded** Authenticode signature (`WTD_CHOICE_FILE`).
2. If none: compute the file's catalog hash (`CryptCATAdminCalcHashFromFileHandle2`, SHA256 then
   SHA1), find a catalog containing it (`CryptCATAdminEnumCatalogFromHash`), and verify
   **via the catalog** (`WTD_CHOICE_CATALOG`). Most in-box Windows binaries, e.g. `notepad.exe`, are
   catalog-signed; skipping this step would mislabel them as unsigned.
3. If still none and the file lives under a **system package root** (`Program Files\WindowsApps`,
   `Windows\SystemApps`) inside a package containing `AppxSignature.p7x`: report
   `UNKNOWN (package)`. MSIX signatures cover the package, not individual files. Only protected
   roots qualify; otherwise an attacker could drop an `AppxSignature.p7x` next to an unsigned binary.

| Result | Meaning |
|--------|---------|
| `VALID` | Chains to a root trusted by this machine. **Not a statement about intent.** |
| `INVALID` | A signature exists but fails (tampered digest, untrusted root, explicitly distrusted, expired without timestamp). |
| `UNSIGNED` | No embedded or catalog signature. **Not evidence of malware** on its own. |
| `UNKNOWN` | Could not be determined (file unreadable, CryptSvc unavailable, packaged app). |

* **Revocation is not checked** (`WTD_REVOKE_NONE`, cache-only URL retrieval) so verification never
  touches the network.
* The signer name is shown only for `VALID`: the subject name inside a broken signature is
  attacker-chosen text.
* The file is opened once and the same handle is used for every check, so it cannot be swapped
  between the embedded and catalog verification.

## Hashing (Phase 1)

SHA256, streamed in 1 MB chunks, cached by `(path, size, mtime)`. Files over
`hash_max_file_size_mb` (default 256) are skipped with `TOO_LARGE`. Non-regular files are refused
before opening (opening some device paths can block). The fingerprint is re-checked on the open
handle after hashing, and a hash of a file that changed mid-read is not cached.

## Privileges (Phase 1)

**API:** `GetTokenInformation(TokenElevation)` on WinSentinel's own token.

Under UAC an administrator normally runs with a *filtered* token; only "Run as administrator"
yields an elevated one. `TokenElevation` reports the effective state, unlike the deprecated
`IsUserAnAdmin`. WinSentinel never requests elevation itself.

Implementation gotcha: the size-probing call to `GetTokenInformation` fails with
`ERROR_INSUFFICIENT_BUFFER` for variable-size classes but `ERROR_BAD_LENGTH` for fixed-size ones
such as `TokenElevation`.

---

## Network (Phases 2–3)

### 1. Socket tables with owner, creation time and service

**APIs:** `iphlpapi!GetExtendedTcpTable(TCP_TABLE_OWNER_MODULE_ALL)` and
`GetExtendedUdpTable(UDP_TABLE_OWNER_MODULE)`, each for `AF_INET` and `AF_INET6`; then
`GetOwnerModuleFromTcpEntry` / `Tcp6` / `Udp` / `Udp6` with `TCPIP_OWNER_MODULE_INFO_BASIC`.

| Row field | Notes |
|-----------|-------|
| `dwOwningPid` | PID that created the socket — the basis of process ↔ network correlation |
| `liCreateTimestamp` | FILETIME when the socket was created (measured: populated on every row, ms accuracy) |
| `dwLocalPort` / `dwRemotePort` | **network byte order** in the low 16 bits of a DWORD |
| `dwLocalAddr` (IPv4) | address bytes in network order; on little-endian CPUs read the DWORD bytes as-is |
| `ucLocalAddr[16]` (IPv6) | raw 16 bytes |
| `dwState` | `MIB_TCP_STATE`: 1 CLOSED … 5 ESTABLISHED … 12 DELETE_TCB. UDP has no state |

Row sizes on x64: TCPv4 160, TCPv6 192, UDPv4 160, UDPv6 176 bytes. The table header is a
`DWORD` count followed by rows at the row's alignment (8 bytes on x64), which WinSentinel lets
ctypes compute instead of hard-coding.

* **Why `OWNER_MODULE` and not `OWNER_PID` (psutil's choice):** the creation timestamp makes "the
  process connected N seconds after starting" exact regardless of polling interval, and lets
  correlation reject a socket older than the process currently holding its PID. The owner module
  names the **service** inside `svchost.exe` (e.g. `svchost.exe (RpcSs)`).
* **Permissions:** tables need none. Owner-module lookup works for most sockets as a standard user
  (measured 33 of 37); protected owners return `ERROR_ACCESS_DENIED`, which is cached so it is not
  retried every poll.
* **Limitations:** snapshots miss short-lived connections; UDP rows have no remote endpoint;
  kernel-mode sockets (SMB, `http.sys` used by IIS/WinRM) are owned by PID 4; `TIME_WAIT` rows can
  report PID 0 after the owner releases the socket.
* **On failure:** each of the four tables is independent; a failing table is listed in
  `unavailable_tables` while the others are still returned.
* **Alternatives:** psutil `net_connections`, `netstat -ano`, ETW `Microsoft-Windows-Kernel-Network`
  (sees short-lived connections; admin), WFP auditing (admin).

### 2. Direction is inferred

The tables do not record who initiated a TCP connection. WinSentinel marks a connected socket
**inbound** when its local port is listened on at the same (or wildcard `0.0.0.0` / `::`) address,
otherwise **outbound**. TCP `LISTEN` rows are *listening*; UDP rows are *bound*.

### 3. Address scope

`LOOPBACK`, `LINK_LOCAL`, `MULTICAST`, `UNSPECIFIED`; `PRIVATE` = RFC 1918, carrier-grade NAT
(100.64.0.0/10) and IPv6 unique-local (fc00::/7); `PUBLIC` = globally routable; everything else
(documentation, benchmarking, broadcast ranges) is `RESERVED`. IPv4-mapped IPv6 addresses are
classified by their IPv4 part. Note that Python's `ipaddress.is_private` also covers
documentation ranges, which is why WinSentinel uses its own list.

### 4. Correlation: PID + time, not PID alone

A socket's owner is the most recently created process instance with that PID created **no later
than the socket** (1 s tolerance for millisecond rounding). If every process holding the PID is
newer than the socket, the socket is `PID_REUSE_SUSPECTED` rather than blamed on an unrelated
program. The running engine keeps exited processes for `engine.exit_retention_seconds`, so
lingering sockets of a process that just exited are still attributed correctly, and resolves a
PID it has not seen yet (a process born between polls) on demand.

---

## Engine (Phase 4)

### Background enrichment priority

**API:** `SetThreadPriority(GetCurrentThread(), THREAD_MODE_BACKGROUND_BEGIN)` on the enrichment
thread. Windows lowers that thread's CPU priority **and its I/O and memory priority**, so hashing
executables yields to foreground applications. No privileges required; failure is harmless.

### Single instance

**API:** `msvcrt.locking` → `LockFile` on `%LOCALAPPDATA%\WinSentinel\engine.lock`. The byte-range
lock is released by Windows when the process exits, even on a crash, so there are no stale lock
files to clean up. A second `winsentinel monitor` for the same user fails immediately with a clear
message.

### Status file

`engine-status.json` is written to a temporary file in the same directory and renamed over the
target (`MoveFileExW` with replace semantics via `Path.replace`), so readers never see a partial
file. `winsentinel status` validates it against the schema, and only reports the engine as running
if the status is fresh **and** the recorded PID still belongs to the same process instance
(`process_key`), so a file left behind by a crashed engine is never shown as running.

### Timeouts without killing threads

Python cannot safely terminate a thread blocked inside a Windows API. Each collector runs on its
own thread; a watchdog marks a run that exceeds `collectors.collector_timeout_seconds` as
`TIMED_OUT` (reported in `status` and as a `COLLECTOR_STATUS` event) while every other component
keeps working. Worker threads are daemon threads so a hung system call cannot prevent exit.

---

## Storage (Phase 7)

SQLite in **WAL** journal mode: readers (`events`, `alerts`, `db info` from another terminal) never
block the engine's writer. A single writer thread batches inserts and flushes on shutdown, so
Ctrl+C does not lose buffered events. Read commands open the file read-only (`mode=ro` URI). No
special permissions: the database lives under `%LOCALAPPDATA%\WinSentinel`.

---

## Dashboard input (Phase 9)

**API:** `msvcrt.kbhit` / `msvcrt.getwch` on a daemon thread. Windows consoles have no `select()` on
stdin, so the reader polls every 50 ms and queues keys for the render loop. Arrow keys arrive as a
two-character sequence (`\x00` or `\xe0` then a scan code). When stdin is not a console (piped,
redirected, a test), the reader does nothing and the dashboard still renders.

---

## Response actions (Phase 10)

### Suspend and resume

**API:** `OpenProcess(PROCESS_SUSPEND_RESUME)` → `ntdll!NtSuspendProcess` / `NtResumeProcess`.

* **Why:** suspending freezes every thread without destroying state, so it is the safe, reversible
  first response. The documented alternative, `SuspendThread` per thread, races with threads the
  process creates while you iterate.
* **Permissions:** a standard user can suspend their own processes. Other users' and SYSTEM
  processes need Administrator. **Protected (PPL) processes refuse even an administrator.**
* **Failure:** `ERROR_ACCESS_DENIED` is reported as a failed action with an explanation. Nothing is
  retried or escalated.
* **Limitation:** these are undocumented but stable ntdll exports (used by Sysinternals Process
  Explorer). Suspension counts nest: two suspends need two resumes.

### Terminate

**API:** `OpenProcess(PROCESS_TERMINATE)` → `TerminateProcess(handle, 1)`. Immediate and
irreversible: no cleanup handlers run, unsaved data is lost. Same permission rules as suspend.

### PID-reuse guard

Before every action the process is re-read with `NtQuerySystemInformation`, and the action proceeds
only if `(PID, creation time)` still matches what the user saw. There is still a window of a few
milliseconds between that check and `OpenProcess`. Closing it fully would mean comparing the
creation time *through the opened handle* (`GetProcessTimes`); this is a known, documented gap.

### Firewall

**Interface:** `netsh advfirewall firewall add|delete|show rule`, run without a shell.

* **Why netsh and not the `INetFwPolicy2` COM API:** no COM/pywin32 dependency, identical rule
  semantics, and output a user can reproduce by hand. The trade-off is parsing localised text:
  `list` matches the `Rule Name:` label, which is English-only. On non-English Windows, `list` may
  show nothing, but block/unblock still work.
* **Permissions:** Administrator. Without elevation netsh fails and the error says so.
* **Scope:** outbound block rules by remote IP, remote port, or program path. WinSentinel never
  edits or deletes rules it did not create.

---

## Persistence (Phases 11–12)

| Source | API | Standard user | Notes |
|--------|-----|---------------|-------|
| `Run` / `RunOnce` (HKCU, HKLM, WOW6432Node) | `winreg.OpenKey` + `EnumValue` | Readable | Commands are split with `CommandLineToArgvW` to find the executable |
| Startup folders (per-user, all-users) | directory listing | Readable | `.lnk` targets are not resolved (would need `IShellLink` COM) |
| Scheduled tasks | parse XML files under `%SystemRoot%\System32\Tasks` | **Mostly denied** | The folder ACL admits only Administrators/SYSTEM, so this source is usually empty when not elevated. The Task Scheduler COM API has the same restriction |
| Auto-start services | `psutil.win_service_iter` (`EnumServicesStatusEx` + `QueryServiceConfig`) | Readable | Only `automatic` start types count as persistence |

Each source is isolated: a failure is recorded in `unavailable_sources` and the others still
return. The monitor polls every 30 s (`engine.persistence_interval_seconds`). The first poll is
inventory, and only later additions produce `PERSISTENCE_ADDED`. Registry change notifications
(`RegNotifyChangeKeyValue`) would be faster but need one waiting thread per key; polling a few
keys every 30 s is cheaper and simpler.

---

## File monitor (Phase 12)

**API:** `ReadDirectoryChangesW`, through the `watchdog` library's Windows observer.

* **Why:** event-driven, so there is no per-file polling cost and no missed changes between polls,
  within the kernel buffer's limits.
* **Scope:** only the Startup folders, `%TEMP%` and `Downloads` by default
  (`file_monitor.monitored_paths` overrides this). Watching whole volumes is deliberately
  unsupported.
* **Permissions:** read access to each directory. Paths that cannot be watched are reported in
  `status` as degraded, not fatal.
* **Limitations:** a burst of changes can overflow the kernel buffer and drop notifications.
  Events do not say *which process* wrote the file, so FILE-001 detections are unattributed. Rapid
  `MODIFIED` notifications are debounced per path (1 s).

---

## Not implemented: event log and DNS

* **Process creation from the Security log (event 4688)** needs Administrator to read the Security
  channel *and* the "Audit Process Creation" policy (off by default). Command lines in 4688 need a
  second policy.
* **Per-process DNS**: the `Microsoft-Windows-DNS-Client/Operational` channel is disabled by default,
  and enabling it needs Administrator. ETW DNS tracing needs Administrator too.

Neither adds anything for the default standard-user run, so both are left as roadmap items rather
than collectors that silently return nothing.
