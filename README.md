# ThreatLens

> **See what your Windows system is doing. Detect what shouldn't be happening. Respond safely.**

ThreatLens is a transparent, local-first, defensive host-security and activity-monitoring CLI for
Windows 10/11 — a lightweight, educational EDR. It shows *what* is happening, explains *why*
something may be suspicious, and leaves every response decision to you.

It sends no telemetry, never hides itself, and never takes automatic action.

## Status

**All 14 phases are complete.** ThreatLens ships as a CLI and as a single-file
`ThreatLens.exe`; running the executable with no arguments opens the live btop-style dashboard.
The `threatlens` command is available in both **PowerShell** and **Command Prompt (cmd)** — see
[Option C](#option-c--threatlens-in-every-shell-powershell-and-cmd).

| Area | What works |
|------|-----------|
| Visibility | Processes, lineage, sockets (owning PID + service), persistence/autostart, file activity |
| Correlation | Process ↔ network ↔ lineage, joined by PID **and** kernel creation time (PID-reuse safe) |
| Detection | 17 evidence-based rules across origin, signature, masquerade, lineage, execution, network, persistence and file activity |
| Scoring | Noisy-OR risk scoring with a corroboration bonus and conservative caps; alerts you triage |
| Storage | Local SQLite (WAL), migrations, retention, crash-safe batched writes |
| Dashboard | Live multi-panel screen (`monitor`, the default) with keyboard controls |
| Response | Suspend / resume / terminate with a protected-process safety layer and PID-reuse guard; firewall block/unblock; every action confirmed and audited |
| Baselines | Capture a known-good picture, then see exactly what's new; allowlist by path / SHA256 / signer |

Deferred as clearly-scoped roadmap items: event-log ingestion and per-process DNS (both gated
behind Administrator rights and machine policy — see [architecture §15](docs/architecture.md#15-implementation-phases)).

## Requirements

* Windows 10 (1709+) or Windows 11, 64-bit
* Python 3.12+
* No administrator rights required (see [Permissions](#permissions))

## Installation

### Option A — the standalone executable

Build a single-file `ThreatLens.exe` that needs no Python installed:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"          # dev extras include PyInstaller
pyinstaller ThreatLens.spec --noconfirm
```

This produces `dist\ThreatLens.exe` (~17 MB). Copy it anywhere and run it:

```powershell
.\ThreatLens.exe                 # opens the live dashboard
.\ThreatLens.exe processes       # or any command
```

Double-clicking `ThreatLens.exe` in a terminal (or from Explorer) with no arguments launches the
btop-style dashboard.

### Option B — from source

```powershell
py -3.12 -m venv .venv
.venv\Scripts\activate
pip install -e .
threatlens --help
```

If activation is blocked by the execution policy, run
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` first (current window only), or call
`.venv\Scripts\threatlens.exe` directly. (The pip console command is `threatlens`; the packaged
executable is `ThreatLens.exe` — same program.)

### Option C — `threatlens` in every shell (PowerShell and cmd)

To run `threatlens` from any PowerShell or Command Prompt window, without activating a virtual
environment first, install it into your regular Python. Run this from the repository folder in a
window where no virtual environment is active:

```powershell
py -m pip install -e .
```

pip places `threatlens.exe` in Python's `Scripts` folder (for example
`%LOCALAPPDATA%\Programs\Python\Python313\Scripts`), which is on `PATH` when Python was installed
with *Add python.exe to PATH*. Open a **new** terminal and the command works in either shell:

```powershell
# PowerShell
PS C:\Users\you> threatlens monitor
```

```bat
:: Command Prompt
C:\Users\you> threatlens monitor
```

Because the install is editable (`-e`), changes to the source take effect without reinstalling.
If the command is not found, add the folder printed by
`py -c "import sysconfig; print(sysconfig.get_path('scripts'))"` to your user `PATH`.
To remove it: `py -m pip uninstall threatlens`.

## Usage

```powershell
# Processes
threatlens processes --sort memory --limit 15
threatlens processes --name svchost --verify   # + SHA256 and Authenticode signature
threatlens process 4832                        # one process: image, signature, resources, lineage
threatlens tree --pid 8592 --depth 3

# Network
threatlens network --listening                 # every socket with owning process and service
threatlens network --external --json
threatlens connections --external --verify     # active connections grouped by process

# Investigation
threatlens inspect 4832                        # process + sockets + communication chains + detections

# Monitoring
threatlens monitor                             # live dashboard (q to quit)
threatlens monitor --stream                    # line-by-line stream of changes and detections
threatlens monitor --stream --events all --loopback   # include inventory, enrichment, loopback
threatlens monitor --json --duration 300 | Out-File -Encoding ascii events.jsonl
threatlens status                              # engine health (from another terminal) + self-test

# Response (confirmed + audited; firewall needs admin)
threatlens suspend 4832          # freeze a process while you investigate
threatlens resume 4832
threatlens terminate 4832        # irreversible; refuses protected system processes
threatlens clear-ram             # trim working sets to free physical RAM
threatlens firewall block-ip 185.1.2.3
threatlens firewall list | unblock "ThreatLens:ip:185.1.2.3"

# Baselines, allowlist, persistence, history
threatlens baseline create
threatlens baseline compare      # what's new since the baseline
threatlens allow sha256 <HASH> --reason "internal tool"
threatlens persistence           # autostart entries (Run keys, Startup, tasks, services)
threatlens events --type PROCESS_STARTED --since 2h
threatlens alerts | threatlens alerts show <ID> | threatlens alerts set-status <ID> resolved
threatlens db info | cleanup | vacuum

# Rules and configuration
threatlens rules
threatlens rules show PROC-006
threatlens config init | show | path | validate
```

All commands accept `--json`. The full command set is in `threatlens --help`.

Every command works the same in PowerShell and Command Prompt. The examples above use PowerShell
syntax only for redirection: in cmd, replace `| Out-File -Encoding ascii events.jsonl` with
`> events.jsonl` (the JSON output is already ASCII).

Global flags work before or after the command: `--json`, `-q/--quiet`, `-v/--verbose`,
`--no-color`, `--config PATH`, `--version`, `-h/--help`.

### What a detection looks like

```
12:04:11.207  SUSPICIOUS          PROC-005  Windows system binary name from an unexpected location  score +45 · HIGH confidence
              svchost.exe (PID 2520): svchost.exe running from an unexpected directory
              C:\Users\alice\AppData\Local\Temp\lab\svchost.exe
              • [observed] Process is named svchost.exe, the name of a core Windows binary: svchost.exe
              • [observed] Actual location: C:\Users\alice\AppData\Local\Temp\lab\svchost.exe
              • [inferred] The genuine binary runs only from: c:\windows\system32, c:\windows\syswow64
```

Detections are **signals that require investigation, not verdicts**. Each carries a score
contribution (max +60 per rule), a confidence, evidence labelled *observed* or *inferred*, MITRE
ATT&CK references, and — in `inspect` — why it matters and what you can do.

### The dashboard

```
┌──────────────────────────────────────────────────────────────────────────────────────────┐
│  THREATLENS   Windows Security Monitor   v0.1.0   ● MONITORING                           │
│ Processes  301        Connections  92        Alerts  1  (0 critical)    Uptime  00:04:12 │
│ CPU ███──────────────  12%                   RAM ██████████████──  78%  5.7 GB/7.3 GB     │
└──────────────────────────────────────────────────────────────── standard user · every 2s ┘
┌─ PROCESSES  (sort: cpu) ──────────────────────┐┌─ NETWORK  (6 external/active) ───────────┐
│ PID  PROCESS       USER        CPU%  MEM  RISK││ PID  PROCESS   REMOTE        STATE  RISK │
│ ...                                           │└──────────────────────────────────────────┘
│                                               │┌─ ALERTS  (1 active) ─────────────────────┐
│                                               ││   MEDIUM  58 svchost.exe — PROC-005, ... │
│                                               │└──────────────────────────────────────────┘
│                                               │┌─ RECENT ACTIVITY ────────────────────────┐
└───────────────────────────────────────────────┘└──────────────────────────────────────────┘
                     Select a process with ↑/↓ to stop it.
  ↑↓ select   T stop   C clear RAM   P/M/N sort   L loopback   Space pause   Q quit
```

| Key | Action |
|-----|--------|
| ↑ ↓ PgUp PgDn Home End | Select a process. The highlight follows the process even when the list re-sorts |
| **T** or **Delete** | Stop (terminate) the selected process. A panel shows its PID, name, path and user, and nothing happens until you press **Y**. Protected Windows processes are refused |
| **C** | Clear RAM: trim the working sets of every process you can access (see below). Asks first; runs in the background |
| P / M / N | Sort by CPU / memory / name |
| L | Show loopback connections |
| Space | Pause: freeze the lists so rows stop moving |
| Q or Esc | Quit (Esc closes an open dialog first) |

Every stop and clear-RAM, including cancelled and refused ones, is recorded in the audit log.

**What "Clear RAM" does.** It asks Windows to move each process's idle pages out of physical
memory (`EmptyWorkingSet`, the same as Sysinternals RAMMap's *Empty Working Sets*). "In use" RAM
drops right away and nothing is closed or deleted. Programs page that memory back in when they
next touch it, so they may be briefly slower. Windows already uses free RAM for caching, so this
is useful before starting something memory-hungry, not as a routine speed-up. As a standard user
only your own processes are trimmed; run elevated to include other processes.

## Detection methodology

17 rules across origin, signature, masquerading, lineage, command-line, network, persistence and
file behaviour. Full specifications, false positives and tuning:
[`docs/detection-rules.md`](docs/detection-rules.md).

* **Unknown ≠ malicious, unsigned ≠ malware.** Network and signature rules stay silent for
  executables in trusted locations or with a valid signature; no port is "bad" by itself.
* **Context through correlation.** Lineage is verified (a parent must predate its child); sockets are
  joined to processes by PID *and* kernel creation time; "connected N seconds after start" uses
  kernel timestamps.
* **Measured false-positive control.** On the development machine, all ~295 running processes
  produce zero detections; benign lab stand-ins (a renamed copy of `ping.exe` in Temp, an encoded
  `Start-Sleep`) are detected with the expected rules.
* **No automatic response.** Detection code cannot suspend, terminate or block anything.
* **Combined risk.** Per-process detections combine by noisy-OR, weighted by confidence, plus a
  bonus when independent categories agree. All-LOW evidence is capped at 39 and single-category
  evidence at 59, so one noisy signal cannot reach HIGH. Scores of 40+ raise an alert.

## Permissions

ThreatLens never requests elevation. As a **standard user** you get every process's identity,
lineage, CPU, memory and — for nearly all processes — executable path, hash and signature, plus all
sockets with their owning process. Command line, user and integrity level are available for your
own processes. **Running elevated** adds those for SYSTEM and other users' processes (and lets
command-line rules evaluate them). Protected processes (PPL) remain unreadable even to
administrators. Unavailable fields always show the reason, e.g. `<access denied>`.

See the full [privilege matrix](docs/architecture.md#4-privilege-matrix).

## How it works

* **Processes:** one `NtQuerySystemInformation` call per snapshot (~9 ms steady-state for ~275
  processes) plus one handle per new process; a handle-free kernel query recovers exe paths when
  access is denied.
* **Network:** `GetExtendedTcpTable`/`GetExtendedUdpTable` with the *owner module* table class for
  kernel socket creation times and service names.
* **Engine:** one thread per monitor with backoff and a timeout watchdog; a bounded event bus that
  counts drops; low-priority background enrichment; atomic status file; single-instance lock.
  One failing collector never stops the others.

Details: [`docs/windows-internals.md`](docs/windows-internals.md) · design:
[`docs/architecture.md`](docs/architecture.md).

## Limitations

* Polling misses processes and connections that live shorter than the interval.
* Parent PIDs can be spoofed and command lines rewritten by the process itself.
* Signature revocation is not checked (no network access).
* Location checks use default Windows ACLs, not each folder's actual ACL.
* Scheduled tasks are only visible when running elevated (the Tasks folder is admin-only).
* File events do not identify the writing process.
* Event-log ingestion and per-process DNS are not implemented (both need Administrator and
  non-default machine policy).
* The firewall `list` command parses English `netsh` output.

## Security

See [SECURITY.md](SECURITY.md): what ThreatLens will never do, how it protects itself (secret
redaction, log/terminal-injection defences, strict config and status-file validation, PID-reuse
safety), and known limitations.

## Development

```powershell
pip install -e ".[dev]"
ruff format --check src tests; ruff check src tests
mypy
pytest                                   # unit tests (fakes) + integration tests (real Windows APIs)
python scripts/generate_rule_docs.py     # after changing rule metadata
```

Integration tests only observe benign processes they spawn themselves: sleeping interpreters,
loopback-only sockets, renamed copies of `ping.exe` pinging `127.0.0.1`, and an encoded
`Start-Sleep`. The persistence test adds and removes one value in the current user's own `Run` key.
No test contacts the internet.

To see detections live on your own machine, use the benign lab: [`scripts/lab`](scripts/lab/README.md).

See [CONTRIBUTING.md](CONTRIBUTING.md) and [`docs/troubleshooting.md`](docs/troubleshooting.md).

## License

MIT
