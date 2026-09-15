# Detection Rules

> Generated from the rule metadata in `src/winsentinel/detection/rules/` by
> `scripts/generate_rule_docs.py`. Do not edit by hand.

## How to read a detection

WinSentinel rules produce **signals, not verdicts**. Each detection carries:

| Field | Meaning |
|-------|---------|
| Score | This rule's contribution (1-60). No single rule can reach HIGH or CRITICAL on its own. |
| Confidence | How reliably the signal indicates genuinely suspicious activity. |
| Evidence | Facts labelled **observed** (seen directly) or **inferred** (derived from observations). |
| MITRE ATT&CK | Related technique IDs, for learning and cross-referencing. |

Principles applied by every rule:

* **Unknown is not malicious; unsigned is not malware.** Rules that look at network behaviour or
  missing signatures stay silent for executables in trusted locations or with a valid signature.
* **No hard-coded "bad" ports or addresses.** Port numbers only ever add weak context (NET-004).
* **Context over single facts.** Combined risk scoring (Phase 6) weighs categories together.
* **Rules never act.** Nothing in detection can suspend, terminate or block.

## Evaluation model

| Event | Meaning | Evaluated by |
|-------|---------|--------------|
| `PROCESS_DISCOVERED` | Already running when monitoring began | origin, lineage and command-line rules |
| `PROCESS_STARTED` | First observed after monitoring began | origin, lineage and command-line rules |
| `PROCESS_ENRICHED` | SHA256 and signature became available | signature rules; deferred network rules |
| `CONNECTION_DISCOVERED` / `CONNECTION_OPENED` | Socket present at startup / new | network rules |
| `LISTENER_OPENED` | New listening socket | NET-002 |

Network rules that need the owner's signature **defer** a connection observed before background
enrichment finishes and evaluate it when `PROCESS_ENRICHED` arrives, so a validly signed
application is never flagged merely because its first connection beat the signature check.

`winsentinel inspect <PID>` replays the *current state* of one process through the rules.
Rules that watch change over time (NET-001, NET-002, NET-003) only fire under
`winsentinel monitor`.

## Rule summary

| Rule | Name | Category | Score | Confidence |
|------|------|----------|------:|------------|
| [FILE-001](#file-001--executable-or-script-written-to-a-monitored-sensitive-location) | Executable or script written to a monitored sensitive location | PERSISTENCE | +30 | MEDIUM |
| [NET-001](#net-001--previously-unseen-executable-connects-to-the-internet) | Previously unseen executable connects to the internet | NETWORK | +10 | LOW |
| [NET-002](#net-002--new-listening-port-reachable-from-the-network) | New listening port reachable from the network | NETWORK | +20 | LOW |
| [NET-003](#net-003--high-frequency-or-scan-like-outbound-connections) | High-frequency or scan-like outbound connections | NETWORK | +20 | LOW |
| [NET-004](#net-004--outbound-connection-to-an-uncommon-port) | Outbound connection to an uncommon port | NETWORK | +10 | LOW |
| [PERSIST-001](#persist-001--new-autostart-entry) | New autostart entry | PERSISTENCE | +30 | MEDIUM |
| [PERSIST-002](#persist-002--new-scheduled-task-or-auto-start-service) | New scheduled task or auto-start service | PERSISTENCE | +35 | MEDIUM |
| [PROC-001](#proc-001--executable-running-from-a-temporary-directory) | Executable running from a temporary directory | ORIGIN | +20 | MEDIUM |
| [PROC-002](#proc-002--unsigned-executable-in-a-user-writable-location) | Unsigned executable in a user-writable location | SIGNATURE | +15 | LOW |
| [PROC-003](#proc-003--suspicious-parent-child-process-relationship) | Suspicious parent-child process relationship | LINEAGE | +25 | MEDIUM |
| [PROC-004](#proc-004--new-process-connects-to-the-internet-immediately-after-starting) | New process connects to the internet immediately after starting | NETWORK | +20 | MEDIUM |
| [PROC-005](#proc-005--windows-system-binary-name-from-an-unexpected-location) | Windows system binary name from an unexpected location | MASQUERADE | +45 | HIGH |
| [PROC-006](#proc-006--obfuscated-or-download-and-execute-powershell) | Obfuscated or download-and-execute PowerShell | EXECUTION | +35 | MEDIUM |
| [PROC-007](#proc-007--windows-utility-used-to-download-or-proxy-execute-code) | Windows utility used to download or proxy-execute code | EXECUTION | +35 | MEDIUM |
| [PROC-008](#proc-008--deceptive-executable-file-name) | Deceptive executable file name | MASQUERADE | +40 | HIGH |
| [SIG-001](#sig-001--invalid-executable-signature) | Invalid executable signature | SIGNATURE | +45 | HIGH |
| [TREE-001](#tree-001--program-launched-through-an-interpreter-by-a-document-browser-or-server-process) | Program launched through an interpreter by a document, browser or server process | LINEAGE | +30 | MEDIUM |

## Rules

### FILE-001 — Executable or script written to a monitored sensitive location

**Detects:** An executable or script file was created in a monitored security-relevant directory (a Startup folder, %TEMP%, or Downloads).

**Why it matters:** Malware stages payloads by writing an executable to Temp, and establishes persistence by dropping one into a Startup folder. Seeing a new .exe/.dll/.ps1/.scr appear there is an early signal — well before it necessarily runs. It is only a signal: browsers and installers legitimately write executables to these places.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| PERSISTENCE | +30 | MEDIUM | LOW | `FILE_CREATED`, `FILE_RENAMED` | T1105, T1547.001 |

**Known false positives:**

* Downloading an installer or program (lands in Downloads)
* Installers and self-extracting archives unpacking to %TEMP%
* A user placing a shortcut in their Startup folder

**What to do:** Correlate with process activity: if a new process then runs this file, or it appears in a Startup folder you did not populate, investigate its origin.

### NET-001 — Previously unseen executable connects to the internet

**Detects:** An executable that has not communicated since monitoring began makes its first outbound connection to a public address, and it is outside trusted locations without a valid signature.

**Why it matters:** Programs that were already communicating when monitoring started are part of the inventory. A new, unsigned program in a user-writable location that starts talking to the internet deserves a look. Unknown is not malicious, so this scores low.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| NETWORK | +10 | LOW | NORMAL | `CONNECTION_DISCOVERED`, `CONNECTION_OPENED`, `PROCESS_ENRICHED` | T1071 |

**Known false positives:**

* Any newly installed or first-run unsigned application

**What to do:** Confirm the program is expected; if so, allowlist it by path or hash (baselines arrive in a later phase).

### NET-002 — New listening port reachable from the network

**Detects:** A process outside trusted locations started listening on a non-loopback address after monitoring began.

**Why it matters:** A listener bound to all interfaces or a LAN address accepts inbound connections — exactly what a backdoor or bind shell needs. Loopback listeners (local IPC) and services in trusted locations are not flagged.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| NETWORK | +20 | LOW | LOW | `LISTENER_OPENED` | T1571 |

**Known false positives:**

* Development servers, media casting and LAN discovery in user-installed apps
* Peer-to-peer and game clients

**What to do:** Check which process owns the port, whether Windows Firewall allows it inbound, and whether the user expects a server here.

### NET-003 — High-frequency or scan-like outbound connections

**Detects:** A process outside trusted locations opened an unusually large number of outbound connections, contacted many hosts on the same port, or made many unanswered attempts within a short window.

**Why it matters:** Worm-like propagation, port scanning and beaconing retries produce bursts that ordinary desktop applications outside Program Files rarely do. Polling only observes connections alive at poll time, so real counts are at least as high as reported.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| NETWORK | +20 | LOW | LOW | `CONNECTION_OPENED` | T1046, T1071 |

**Known false positives:**

* Download managers, torrent clients and crawlers
* Network inventory tools run by administrators

**What to do:** Look at the destinations in the evidence: many hosts on one port suggests scanning; repeated attempts to one host suggests a failing beacon.

### NET-004 — Outbound connection to an uncommon port

**Detects:** An executable outside trusted locations and without a valid signature connected to a public address on a port outside the configured common-port list.

**Why it matters:** Remote-access tools and command-and-control channels often use non-standard ports. Port numbers prove nothing — any service can run on any port — so this is the weakest network signal and only adds context to others.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| NETWORK | +10 | LOW | NORMAL | `CONNECTION_OPENED`, `CONNECTION_DISCOVERED`, `PROCESS_ENRICHED` | T1571 |

**Known false positives:**

* Games, VoIP, peer-to-peer and development tools using their own ports
* Self-hosted services on non-standard ports

**What to do:** Check whether the destination and port are expected for this application; extend detection.common_remote_ports if they are.

### PERSIST-001 — New autostart entry

**Detects:** A new registry Run key or Startup-folder entry appeared after monitoring began.

**Why it matters:** Establishing autostart is how malware survives a reboot. A Run key or Startup entry that appears while WinSentinel is watching is worth confirming; the risk is higher when the program it points at lives in a user-writable or temporary location.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| PERSISTENCE | +30 | MEDIUM | LOW | `PERSISTENCE_ADDED` | T1547.001 |

**Known false positives:**

* Installing or updating legitimate software that adds a startup entry
* The user pinning an application to run at login

**What to do:** Confirm you installed or expected this program. Remove the entry (regedit or the Startup folder) if it is unwanted; WinSentinel only reports, never modifies it.

### PERSIST-002 — New scheduled task or auto-start service

**Detects:** A new scheduled task or auto-start service appeared after monitoring began.

**Why it matters:** Scheduled tasks and services are stealthier persistence than Run keys and are common in intrusions. A new one pointing at a user-writable or temporary executable is a strong signal; one in a protected location is usually a software install.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| PERSISTENCE | +35 | MEDIUM | LOW | `PERSISTENCE_ADDED` | T1053.005, T1543.003 |

**Known false positives:**

* Installing software that registers a service or scheduled task
* Windows or driver updates adding maintenance tasks

**What to do:** Verify the task/service is from software you installed. Its executable and command line are in the evidence; investigate if it runs from a user-writable location.

### PROC-001 — Executable running from a temporary directory

**Detects:** A process's executable image is located in a temporary directory.

**Why it matters:** Temporary directories are writable by every user; droppers, downloaders and exploit payloads commonly write their next stage there and run it. Legitimate applications install to Program Files, but installers and updaters also unpack to Temp, so this signal is weak on its own.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| ORIGIN | +20 | MEDIUM | LOW | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1204.002 |

**Known false positives:**

* Installers and updaters that extract themselves to %TEMP% before running
* Programs started directly from inside a ZIP archive (Explorer extracts them to Temp)

**What to do:** Check the parent process and the file's signature and publisher. Confirm whether the user knowingly ran an installer or opened an archive.

### PROC-002 — Unsigned executable in a user-writable location

**Detects:** An executable without any Authenticode signature runs from a location standard users can write to.

**Why it matters:** Code in user-writable locations can be planted without administrator rights, and an absent signature means there is no verifiable publisher. Plenty of legitimate tools are unsigned, so this is a low-confidence signal that gains weight only in combination with others.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| SIGNATURE | +15 | LOW | NORMAL | `PROCESS_ENRICHED` | T1204.002 |

**Known false positives:**

* Unsigned developer tools, scripts compiled locally, portable utilities
* Per-user installs of small open-source applications

**What to do:** Look up the SHA256 in your threat-intelligence source of choice, and confirm the program is expected on this machine. Allowlist it by path or hash if it is.

### PROC-003 — Suspicious parent-child process relationship

**Detects:** A process was started by a parent that does not normally launch that kind of program (e.g. Word starting PowerShell).

**Why it matters:** Attack chains leave characteristic lineage: documents running macros spawn interpreters, WMI remote execution spawns shells under wmiprvse.exe, PsExec-style tools run cmd.exe as a service, and web shells make server processes start shells.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| LINEAGE | +25 | MEDIUM | LOW | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1059 |

**Known false positives:**

* Office add-ins or macros that legitimately automate tasks through cmd/PowerShell
* Administrators using WMI or PsExec for remote management

**What to do:** Review the child's command line and what the parent had open (document, e-mail, web page) when it happened.

### PROC-004 — New process connects to the internet immediately after starting

**Detects:** An executable outside trusted locations and without a valid signature opened an outbound connection to a public address within seconds of starting.

**Why it matters:** Droppers, loaders and remote-access tools typically phone home the moment they run. The delay is measured with kernel timestamps (process creation vs. socket creation), so it is exact regardless of polling interval.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| NETWORK | +20 | MEDIUM | LOW | `CONNECTION_OPENED`, `CONNECTION_DISCOVERED`, `PROCESS_ENRICHED` | T1071, T1105 |

**Known false positives:**

* Unsigned self-updating tools that check for updates on launch
* Portable applications that sync immediately (chat clients, game launchers)

**What to do:** Identify the remote address's owner and what the process sent; check how the executable arrived on the machine.

### PROC-005 — Windows system binary name from an unexpected location

**Detects:** A process uses the name of a core Windows binary but runs from outside its legitimate directory.

**Why it matters:** Malware names itself svchost.exe, lsass.exe or explorer.exe so it blends into process lists. The genuine binaries live only in specific Windows directories, which makes this check precise.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| MASQUERADE | +45 | HIGH | MEDIUM | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1036.005 |

**Known false positives:**

* Copies of system binaries made by backup, forensic or sandbox tools
* Software that ships its own helper with a coincidentally identical name

**What to do:** Inspect the file's signature and hash immediately; genuine system binaries are Microsoft-signed and live under the Windows directory.

### PROC-006 — Obfuscated or download-and-execute PowerShell

**Detects:** PowerShell started with an encoded command, or with a command line that downloads content and executes it.

**Why it matters:** -EncodedCommand hides the script from casual inspection and command-line logging, and 'download then Invoke-Expression' (a download cradle) runs remote code without writing it to disk. Both are staples of malicious PowerShell. ExecutionPolicy Bypass or -NoProfile alone are common in legitimate automation and are not flagged.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| EXECUTION | +35 | MEDIUM | LOW | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1059.001, T1027.010 |

**Known false positives:**

* Management agents and installers that pass scripts via -EncodedCommand to avoid quoting problems
* Bootstrap scripts that install tooling via 'iwr … | iex'

**What to do:** Read the decoded script in the evidence; check what it downloads and from where before allowing it.

### PROC-007 — Windows utility used to download or proxy-execute code

**Detects:** A signed Windows utility (certutil, mshta, rundll32, regsvr32, bitsadmin, msiexec) was invoked with arguments characteristic of downloading or executing untrusted code.

**Why it matters:** 'Living off the land' binaries are Microsoft-signed, so allowlisting and signature checks trust them. Attackers use their side features — certutil's URL cache, mshta's script host, regsvr32's scriptlet loading — to download and run payloads.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| EXECUTION | +35 | MEDIUM | LOW | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1218 |

**Known false positives:**

* Administrators using certutil -urlcache to fetch certificates or CRLs
* Enterprise software deployment running msiexec against an internal URL

**What to do:** Identify the URL or file in the command line and what was written to disk; check the parent process that issued the command.

### PROC-008 — Deceptive executable file name

**Detects:** An executable's name is crafted to look like a document: a double extension, padding before the extension, or a right-to-left override character.

**Why it matters:** invoice.pdf.exe, 'report.docx      .exe' and names using U+202E (which renders 'invoice‮txt.exe' as 'invoiceexe.txt') exist to trick a person into running a program they believe is a document. Legitimate software has no reason to do this.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| MASQUERADE | +40 | HIGH | MEDIUM | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1036.002, T1036.007 |

**Known false positives:**

* Rare: automatically generated file names that happen to contain a dotted document extension

**What to do:** Treat the program as untrusted; find where the file came from (download, e-mail attachment, USB).

### SIG-001 — Invalid executable signature

**Detects:** An executable carries an Authenticode signature that fails verification.

**Why it matters:** A signature that exists but does not verify means the file changed after signing (tampering or patching) or the certificate chain is untrusted, explicitly distrusted or expired. A tampered signed binary is a classic way to borrow a trusted publisher's reputation.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| SIGNATURE | +45 | HIGH | MEDIUM | `PROCESS_ENRICHED` | T1553.002, T1036.001 |

**Known false positives:**

* Old software signed with a certificate that expired without a timestamp (scored +10 LOW; e.g. Git for Windows' usr\bin\bash.exe)
* Software patched or cracked locally by the user

**What to do:** Compare the file hash with the vendor's official release. If the digest does not match, treat the file as untrusted until its origin is explained.

### TREE-001 — Program launched through an interpreter by a document, browser or server process

**Detects:** A process whose parent is a shell or script host, which was itself launched (directly or one level up) by a document application, browser, server process or the WMI host.

**Why it matters:** The three-step chain document/browser/server → interpreter → payload is the typical shape of initial access: the first process is exploited or runs a macro, the interpreter downloads or unpacks, and the last process is the payload.

| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |
|----------|------:|------------|-------|--------------|--------------|
| LINEAGE | +30 | MEDIUM | LOW | `PROCESS_STARTED`, `PROCESS_DISCOVERED` | T1204.002, T1059 |

**Known false positives:**

* Document automation that shells out to helper programs
* Browser-launched installers that use PowerShell (rare)

**What to do:** Reconstruct the chain with 'winsentinel tree' and inspect the final process first; it is the most likely payload.

## Tuning

```toml
[detection]
disabled_rules = ["NET-004"]                       # turn rules off
ignored_executables = ['C:\\Tools\\scanner.exe']   # suppress by full path (never by name)
correlation_window_seconds = 10              # PROC-004
network_burst_window_seconds = 60      # NET-003
network_burst_threshold = 40
network_fanout_threshold = 20
failed_connection_threshold = 15
common_remote_ports = [21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 853, 993, 995, 3478, 5222, 5223, 5228, 8080, 8443]                    # NET-004
trusted_paths = ['C:\Windows\System32', 'C:\Program Files', 'C:\Program Files (x86)']
```

Trusted paths reduce noise but are not blind spots: masquerading (PROC-005), deceptive names
(PROC-008), invalid signatures (SIG-001), suspicious lineage and command lines still apply there,
and user-writable folders *inside* trusted paths (e.g. `C:\Windows\System32\spool\drivers\color`)
are never treated as trusted.

## Known gaps

* **Polling misses short-lived processes.** A `certutil -decode` that finishes in milliseconds is
  never observed, so PROC-007 cannot see it. ETW/Sysmon integration is on the roadmap.
* **Command lines are unreadable for other users' processes without elevation**, which silences
  PROC-006/PROC-007 for those processes.
* **Location checks use default ACLs**, not the real ACL of each folder (findings are labelled
  *inferred*).
* **Persistence (PERSIST-001/002) and baseline (BASE-001) rules** arrive with their monitors in later
  phases.
