# ThreatLens test lab

Benign, self-cleaning scenarios you can run on your own machine to see ThreatLens work. None of
these are malicious: they use harmless stand-ins (a renamed copy of Windows' own `ping.exe`, an
encoded `Start-Sleep`, a loopback socket) and clean up after themselves.

Run ThreatLens in one terminal and a lab script in another:

```powershell
# terminal 1
threatlens monitor --stream --events all
# or the dashboard:
threatlens monitor

# terminal 2
python scripts\lab\run_lab.py --all
```

## Scenarios

| # | Scenario | What ThreatLens should show |
|---|----------|------------------------------|
| 1 | `--http-server` — `python -m http.server` on a port | `python.exe`, a new `LISTENER_OPENED` on that port, NET-002 |
| 2 | `--child-exe` — copy `ping.exe` to `%TEMP%`, run it | `PROCESS_STARTED`, PROC-001 (temp), and it pings only 127.0.0.1 |
| 3 | `--masquerade` — copy `ping.exe` to `%TEMP%\svchost.exe`, run it | PROC-005 (system-binary name from an unexpected location), an alert |
| 4 | `--deceptive` — copy `ping.exe` to `invoice.pdf.exe`, run it | PROC-008 (deceptive name) |
| 5 | `--encoded-ps` — PowerShell with a base64 `Start-Sleep` | PROC-006 with the decoded script in the evidence |
| 6 | `--chain` — `cmd.exe` → `powershell.exe` child chain | TREE-001 / PROC-003 lineage signals |
| 7 | `--drop-file` — write an `.exe` into `%TEMP%`, then delete it | `FILE_CREATED`, FILE-001, `FILE_DELETED` |
| 8 | `--run-key` — add and remove a **HKCU** Run value | `PERSISTENCE_ADDED`, PERSIST-001, `PERSISTENCE_REMOVED` |

Everything is loopback-only; no traffic leaves the machine. Scenario 8 touches only the current
user's own registry hive and always removes its test value.
