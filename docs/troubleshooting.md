# Troubleshooting

## Many fields show `<access denied>`

Expected when running as a standard user: Windows does not let an unelevated process read the
command line, user or integrity level of SYSTEM or other users' processes. Run the terminal with
**Run as administrator** for fuller visibility. Protected processes (`csrss.exe`, `smss.exe`,
`lsass.exe` with RunAsPPL, Defender) remain unreadable even then — that is Windows' protection
working as designed. Exe paths are still available for nearly all processes.

Consequence for detection: rules that read command lines (PROC-006, PROC-007) cannot evaluate
other users' processes without elevation.

## `CPU%` shows `-`

CPU usage needs two samples. `processes`, `process` and `inspect` sample over `--sample` seconds
(default 0.5). `--sample 0` skips CPU entirely.

## `processes --verify` is slow the first time

Each unique executable is hashed and its signature verified once (a few seconds for a few hundred
processes, dominated by hashing large binaries). Results are cached for the rest of the run.

## A Store app shows `Signature: UNKNOWN (package)`

MSIX/AppX apps are signed as a package, not per file. See `docs/windows-internals.md`.

## `System Idle Process` shows high CPU

Its "CPU" is idle capacity. It is sorted last in `--sort cpu`.

## A socket shows `<pid reused>`, `<kernel>` or `<unattributed>`

* `<pid reused>` — the socket is older than the process that now holds its PID; the original owner
  exited. WinSentinel refuses to blame the new process.
* `<kernel>` — owned by PID 4 (System): SMB, or `http.sys` listeners registered by IIS, WinRM or
  other services. The registering application is not visible in the socket table.
* `<unattributed>` — PID 0 (a lingering `TIME_WAIT` entry) or a process that could not be found.

## `winsentinel monitor` says another monitor is already running

Only one engine runs per user. `winsentinel status` shows the running one (PID, uptime). The lock is
released automatically when that process exits, even if it crashed.

## A process I started does not appear in `monitor`

Polling (default every 2 s) misses processes that start and exit between polls, e.g. a
`certutil -decode` that completes in milliseconds. Lower `--interval` narrows the gap but cannot
close it; event-driven sources (ETW/Sysmon) are on the roadmap.

## `monitor` shows no connections for an application

By default the stream hides loopback connections (`--loopback` shows them) and does not print
inventory (sockets that existed at startup; `--events all` shows them). UDP endpoints on ephemeral
ports (49152+) are not reported as listeners.

## `inspect` shows no detections but `monitor` reported one

`inspect` evaluates the current state of one process. Rules that watch change over time — a
listener opening (NET-002), first-seen communication (NET-001), connection bursts (NET-003) — only
fire in the running engine.

## A trusted application is flagged

Every rule documents known false positives (`winsentinel rules show <RULE_ID>` or
`docs/detection-rules.md`). To silence an executable, add its **full path** to
`detection.ignored_executables`; to turn a rule off, add its ID to `detection.disabled_rules`.
Allowlisting by hash or signer arrives with baselines.

## Git Bash's `bash.exe` shows SIG-001 (+10, LOW)

Git for Windows ships `usr\bin\bash.exe` signed with a certificate that expired without a
timestamp, so Windows reports the signature as not valid. WinSentinel scores this case lowest and
says so in the evidence.

## Saving JSON output from Windows PowerShell 5.1

Windows PowerShell 5.1's `>` and `Out-File` write **UTF-16** by default, and piping one native
program into another re-encodes text (adding a BOM). WinSentinel's own output is ASCII JSON, so:

```powershell
winsentinel processes --json | Out-File -Encoding ascii procs.json      # save to a file
$data = winsentinel network --json | Out-String | ConvertFrom-Json      # use in PowerShell
winsentinel monitor --json --duration 60 | Out-File -Encoding ascii events.jsonl
```

PowerShell 7 and `cmd.exe` redirection (`>`) write the bytes unchanged.

## Stderr hint lines appear in red as `NativeCommandError` in PowerShell 5.1

PowerShell 5.1 wraps any stderr text from native programs in an error record. The command
succeeded; check `$LASTEXITCODE` (0 = success).

## Exit codes

| Code | Meaning |
|-----:|---------|
| 0 | success |
| 1 | runtime error (also: another monitor already running; a `status` self-test failed) |
| 2 | usage / invalid configuration / unknown rule or event category |
| 3 | insufficient privileges |
| 4 | target not found (e.g. PID exited) |
| 5 | cancelled by user |
| 6 | blocked by safety policy |
| 130 | interrupted (Ctrl+C) outside `monitor` (`monitor` treats Ctrl+C as a normal stop: 0) |

## Configuration errors

`winsentinel config validate` prints each invalid key with the reason. Unknown keys are rejected
on purpose so typos never silently fall back to defaults. `winsentinel config init` writes a
commented template.
