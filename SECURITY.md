# Security Policy

WinSentinel is a **defensive**, local-first host monitor intended for your own Windows machines or
systems you are authorised to monitor.

## What WinSentinel will never do

WinSentinel does not hide itself, evade or disable security products (including Windows Defender
and Windows Firewall), capture keystrokes or credentials, inject code into other processes, hide
processes or connections, delete evidence, create stealth persistence, intercept or decrypt
TLS, or send telemetry anywhere. Response actions always require an explicit user command and
confirmation, and every outcome (succeeded, failed, cancelled, denied by policy) is written to the
audit log. Detection never triggers a response.

## Security design of WinSentinel itself

| Threat | Control |
|--------|---------|
| Secrets in command lines reaching logs/DB/terminal | Redacted at collection time (`security/redaction.py`), on by default |
| Log forging via crafted process names | Control characters escaped in every log record (`logging_config.py`) |
| Terminal escape / Rich markup / bidi-override injection via process names or paths | All untrusted text rendered through `sanitize_display` + `rich.text.Text`, never markup; anomalies escaped visibly, not removed |
| Malicious configuration | Size-limited, parsed with stdlib `tomllib`, strict schema (`extra="forbid"`), bounded numbers, absolute paths only |
| Command injection | No `os.system`, no `shell=True`. Windows APIs are called directly; the one subprocess (`netsh`) gets a fixed executable and an argument list, with IPs/ports validated first |
| Wrong-process actions due to PID reuse | Processes identified by `(PID, creation time)`; suspend/resume/terminate re-read the process and refuse unless its `process_key` still matches the one shown to the user |
| Crashing Windows by killing a critical process | Protected-process policy refuses suspend/terminate for kernel pseudo-processes, `csrss`/`wininit`/`winlogon`/`services`/`lsass`/`smss`, SYSTEM-integrity processes, configured names, and WinSentinel itself; override needs `--force-protected` **and** confirmation |
| Unattended destructive actions | Confirmation is required; without a terminal and without `--yes` the action is cancelled, never assumed |
| Weakening the firewall | WinSentinel only adds block rules named `WinSentinel:…` and refuses to delete any rule without that prefix; each change is audited and reversible with `firewall unblock` |
| Allowlist spoofing | Allowlisting by process name is rejected; entries match by SHA256, valid-signature signer, or full path (with a warning that paths are the weakest) |
| Misleading trust claims | Signer shown only for VALID signatures; MSIX handling only under protected system roots; revocation-not-checked documented |
| Wrong socket blamed on a process due to PID reuse | Sockets joined to processes by PID **and** kernel creation time; mismatches marked `PID_REUSE_SUSPECTED` |
| Forged or stale engine status | `engine-status.json` is size-limited and schema-validated; "running" requires a fresh timestamp and a live process with the same process key |
| Two engines corrupting shared files | Crash-safe exclusive lock (`LockFile`) on `engine.lock`; atomic replace for the status file |
| Detection evasion by naming a binary like WinSentinel | Self-exclusion is by exact process instance (PID + creation time) of the running engine and its launcher chain only — never by name or path |
| Detection logic triggering actions | Detection code has no access to response functionality; rules only return evidence |
| SQL injection | Parameterised queries only; the few table names interpolated come from fixed in-code tuples |
| Resource exhaustion | Bounded event queue (drop-oldest, counted), bounded enrichment queue, bounded caches and rule history, hashing size limit, recursion depth cap |

## Known limitations with security impact

* **Polling misses short-lived processes and connections.** Activity that starts and ends between
  two polls is never seen; detections that depend on it cannot fire.
* **`detection.ignored_executables` and `detection.trusted_paths` reduce visibility.** Anyone who can
  edit the configuration can silence findings for a path; keep the config file writable only by
  the account that runs WinSentinel.
* **Parent PID spoofing** is not detectable by polling.
* **Command lines can be modified by the process itself** after launch.
* **Revocation is not checked** during signature verification (offline-first).
* **Elevated use with a user-writable config.** If WinSentinel runs elevated but reads
  `%LOCALAPPDATA%\WinSentinel\config.toml`, any process running as that user could weaken settings.
  When running elevated for long periods, point `--config` at a file writable only by
  Administrators. The same applies to the database, which holds the allowlist. An automatic ACL
  check is not implemented yet.
* **Path-based allowlist entries** exempt whatever file sits at that path. Prefer `allow sha256`.
* **`--force-protected` is a real override.** It exists for experts; using it on a critical
  process can bugcheck the machine.

## Reporting a vulnerability

Please report suspected vulnerabilities privately to the maintainers rather than opening a
public issue. Include the WinSentinel version (`winsentinel --version`), Windows build, and
reproduction steps. Do not include real credentials or sensitive telemetry in reports.
