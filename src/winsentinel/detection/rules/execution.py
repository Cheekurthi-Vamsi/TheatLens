"""Rules about how processes were launched: lineage and command lines."""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from winsentinel.core.interfaces import StateView
from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    Evidence,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
)
from winsentinel.detection.catalog import (
    BROWSERS,
    DOCUMENT_HANDLERS,
    INTERPRETERS,
    POWERSHELL,
    SERVER_PROCESSES,
    suspicious_parent_child,
)
from winsentinel.detection.rules.base import Rule, inferred, observed
from winsentinel.security.redaction import redact_command_line

PROCESS_APPEARANCE: Final = (EventType.PROCESS_STARTED, EventType.PROCESS_DISCOVERED)
MAX_COMMAND_EVIDENCE_CHARS: Final = 300
MAX_DECODED_PREVIEW_CHARS: Final = 200


def _truncate(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


class SuspiciousParentChild(Rule):
    meta = RuleMetadata(
        rule_id="PROC-003",
        name="Suspicious parent-child process relationship",
        description=(
            "A process was started by a parent that does not normally launch that kind of program "
            "(e.g. Word starting PowerShell)."
        ),
        rationale=(
            "Attack chains leave characteristic lineage: documents running macros spawn "
            "interpreters, WMI remote execution spawns shells under wmiprvse.exe, PsExec-style "
            "tools run cmd.exe as a service, and web shells make server processes start shells."
        ),
        category=RuleCategory.LINEAGE,
        event_types=PROCESS_APPEARANCE,
        base_score=25,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1059",),
        false_positives=(
            "Office add-ins or macros that legitimately automate tasks through cmd/PowerShell",
            "Administrators using WMI or PsExec for remote management",
        ),
        recommendation=(
            "Review the child's command line and what the parent had open (document, e-mail, web "
            "page) when it happened."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None:
            return None
        parent = state.parent_of(process)
        if parent is None:
            return None
        verdict = suspicious_parent_child(parent.name, process.name)
        if verdict is None:
            return None
        explanation, techniques = verdict
        evidence = [
            observed(
                f"{parent.name} (PID {parent.pid}) started {process.name} (PID {process.pid})",
                "parent",
                parent.exe or parent.name,
            ),
            inferred(explanation),
        ]
        if process.command_line:
            evidence.append(
                observed(
                    "Child command line",
                    "cmdline",
                    _truncate(process.command_line, MAX_COMMAND_EVIDENCE_CHARS),
                )
            )
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"started by {parent.name}",
            event=event,
            mitre=techniques,
        )


class UnusualExecutionChain(Rule):
    meta = RuleMetadata(
        rule_id="TREE-001",
        name="Program launched through an interpreter by a document, browser or server process",
        description=(
            "A process whose parent is a shell or script host, which was itself launched "
            "(directly or one level up) by a document application, browser, server process or the "
            "WMI host."
        ),
        rationale=(
            "The three-step chain document/browser/server → interpreter → payload is the typical "
            "shape of initial access: the first process is exploited or runs a macro, the "
            "interpreter downloads or unpacks, and the last process is the payload."
        ),
        category=RuleCategory.LINEAGE,
        event_types=PROCESS_APPEARANCE,
        base_score=30,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1204.002", "T1059"),
        false_positives=(
            "Document automation that shells out to helper programs",
            "Browser-launched installers that use PowerShell (rare)",
        ),
        recommendation=(
            "Reconstruct the chain with 'winsentinel tree' and inspect the final process first; "
            "it is the most likely payload."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.name.lower() == "conhost.exe":
            return None
        chain = state.ancestors(process, limit=4)
        if not chain or chain[0].name.lower() not in INTERPRETERS:
            return None
        interpreter = chain[0].name.lower()
        origin_index = None
        for index, ancestor in enumerate(chain[1:], start=1):
            name = ancestor.name.lower()
            if name in DOCUMENT_HANDLERS or name in SERVER_PROCESSES or name == "wmiprvse.exe":
                origin_index = index
                break
            # Browsers launch native-messaging hosts through cmd.exe legitimately.
            if name in BROWSERS and interpreter != "cmd.exe":
                origin_index = index
                break
        if origin_index is None:
            return None
        lineage = [*reversed(chain[: origin_index + 1]), process]
        rendered = " → ".join(f"{p.name} ({p.pid})" for p in lineage)
        evidence = [
            observed("Verified process chain", "chain", rendered),
            inferred(
                f"{lineage[0].name} reached {process.name} through the interpreter {chain[0].name}"
            ),
        ]
        return self.result(
            process=process, evidence=evidence, detail=f"chain {rendered}", event=event
        )


_ENCODED_FLAGS: Final = frozenset({"ec", *("encodedcommand"[:i] for i in range(1, 15))})
_WINDOW_FLAGS: Final = frozenset("windowstyle"[:i] for i in range(1, 12))
_SCRIPT_START_FLAGS: Final = frozenset(
    {*("command"[:i] for i in range(1, 8)), *("file"[:i] for i in range(1, 5))}
)
_DOWNLOAD: Final = re.compile(
    r"\b(downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|iwr|irm|"
    r"net\.webclient|start-bitstransfer)\b",
    re.IGNORECASE,
)
_EXECUTE: Final = re.compile(r"\b(iex|invoke-expression)\b", re.IGNORECASE)


def _flag(argument: str) -> str | None:
    if len(argument) > 1 and argument[0] in "-/":
        return argument.lstrip("-/").lower() or None
    return None


@dataclass(frozen=True, slots=True)
class PowerShellInvocation:
    encoded: str | None
    hidden_window: bool


def parse_powershell(arguments: Sequence[str]) -> PowerShellInvocation:
    """Extract the parameters that matter, honouring PowerShell's prefix abbreviations.

    Parsing stops at ``-Command``/``-File``: whatever follows is script text or script arguments.
    """
    encoded: str | None = None
    hidden = False
    items = list(arguments[1:])
    for index, argument in enumerate(items):
        name = _flag(argument)
        if name is None:
            continue
        if name in _SCRIPT_START_FLAGS:
            break
        value = items[index + 1] if index + 1 < len(items) else None
        if name in _ENCODED_FLAGS and value is not None:
            encoded = value
        elif name in _WINDOW_FLAGS and value is not None and value.lower().startswith(("h", "1")):
            hidden = True
    return PowerShellInvocation(encoded=encoded, hidden_window=hidden)


def decode_encoded_command(value: str) -> str | None:
    """``-EncodedCommand`` is base64 of UTF-16LE script text."""
    try:
        raw = base64.b64decode(value + "=" * (-len(value) % 4), validate=True)
        return raw.decode("utf-16-le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None


class SuspiciousPowerShell(Rule):
    meta = RuleMetadata(
        rule_id="PROC-006",
        name="Obfuscated or download-and-execute PowerShell",
        description=(
            "PowerShell started with an encoded command, or with a command line that downloads "
            "content and executes it."
        ),
        rationale=(
            "-EncodedCommand hides the script from casual inspection and command-line logging, and "
            "'download then Invoke-Expression' (a download cradle) runs remote code without "
            "writing it to disk. Both are staples of malicious PowerShell. ExecutionPolicy Bypass "
            "or -NoProfile alone are common in legitimate automation and are not flagged."
        ),
        category=RuleCategory.EXECUTION,
        event_types=PROCESS_APPEARANCE,
        base_score=35,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1059.001", "T1027.010"),
        false_positives=(
            "Management agents and installers that pass scripts via -EncodedCommand to avoid "
            "quoting problems",
            "Bootstrap scripts that install tooling via 'iwr … | iex'",
        ),
        recommendation=(
            "Read the decoded script in the evidence; check what it downloads and from where "
            "before allowing it."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.name.lower() not in POWERSHELL or not process.cmdline:
            return None
        invocation = parse_powershell(process.cmdline)
        command_text = " ".join(process.cmdline)
        evidence: list[Evidence] = []
        score = 0
        decoded = None
        if invocation.encoded is not None:
            score = 30
            decoded = decode_encoded_command(invocation.encoded)
            evidence.append(
                observed(
                    "PowerShell received its script via -EncodedCommand",
                    "cmdline",
                    _truncate(command_text, MAX_COMMAND_EVIDENCE_CHARS),
                )
            )
            if decoded is None:
                evidence.append(observed("The encoded value is not valid base64 UTF-16 text"))
            else:
                preview = " ".join(redact_command_line(decoded.split()))
                evidence.append(
                    observed(
                        "Decoded script (secrets redacted, truncated)",
                        "decoded_command",
                        _truncate(preview, MAX_DECODED_PREVIEW_CHARS),
                    )
                )
        searchable = f"{command_text} {decoded or ''}"
        if _DOWNLOAD.search(searchable) and _EXECUTE.search(searchable):
            score = 35
            evidence.append(
                inferred("Downloads content and passes it to Invoke-Expression (download cradle)")
            )
        if not evidence:
            return None
        if invocation.hidden_window:
            evidence.append(observed("Window style is hidden", "window_style", "hidden"))
        detail = "download cradle" if score == 35 else "encoded PowerShell command"
        mitre = ("T1059.001", "T1027.010", "T1105") if score == 35 else self.meta.mitre_techniques
        return self.result(
            process=process, evidence=evidence, detail=detail, event=event, score=score, mitre=mitre
        )


@dataclass(frozen=True, slots=True)
class _LolbinPattern:
    pattern: re.Pattern[str]
    description: str
    techniques: tuple[str, ...]


_Q: Final = r"(?=.*[-/]q(?:n|b|r|f|uiet)?\b)"
LOLBIN_PATTERNS: Final[dict[str, tuple[_LolbinPattern, ...]]] = {
    "certutil.exe": (
        _LolbinPattern(
            re.compile(r"[-/](urlcache|verifyctl)\b"),
            "certutil used to download a file (-urlcache/-verifyctl)",
            ("T1105",),
        ),
        _LolbinPattern(
            re.compile(r"[-/]decode(hex)?\b"),
            "certutil used to decode a file (-decode)",
            ("T1140",),
        ),
    ),
    "mshta.exe": (
        _LolbinPattern(
            re.compile(r"(https?://|javascript:|vbscript:)"),
            "mshta executing a remote or inline script",
            ("T1218.005",),
        ),
    ),
    "rundll32.exe": (
        _LolbinPattern(
            re.compile(r"(javascript:|mshtml\s*,\s*#?\s*runhtmlapplication)"),
            "rundll32 executing script through mshtml",
            ("T1218.011",),
        ),
    ),
    "regsvr32.exe": (
        _LolbinPattern(
            re.compile(r"([-/]i:\s*\"?https?://|scrobj\.dll)"),
            "regsvr32 loading a remote scriptlet (Squiblydoo)",
            ("T1218.010",),
        ),
    ),
    "bitsadmin.exe": (
        _LolbinPattern(
            re.compile(r"[-/](transfer|addfile)\b.*https?://"),
            "bitsadmin downloading a file",
            ("T1197", "T1105"),
        ),
    ),
    "msiexec.exe": (
        _LolbinPattern(
            re.compile(_Q + r"(?=.*https?://)"),
            "msiexec silently installing a package from a URL",
            ("T1218.007",),
        ),
    ),
}


class LolbinProxyExecution(Rule):
    meta = RuleMetadata(
        rule_id="PROC-007",
        name="Windows utility used to download or proxy-execute code",
        description=(
            "A signed Windows utility (certutil, mshta, rundll32, regsvr32, bitsadmin, msiexec) "
            "was invoked with arguments characteristic of downloading or executing untrusted "
            "code."
        ),
        rationale=(
            "'Living off the land' binaries are Microsoft-signed, so allowlisting and signature "
            "checks trust them. Attackers use their side features — certutil's URL cache, "
            "mshta's script host, regsvr32's scriptlet loading — to download and run payloads."
        ),
        category=RuleCategory.EXECUTION,
        event_types=PROCESS_APPEARANCE,
        base_score=35,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1218",),
        false_positives=(
            "Administrators using certutil -urlcache to fetch certificates or CRLs",
            "Enterprise software deployment running msiexec against an internal URL",
        ),
        recommendation=(
            "Identify the URL or file in the command line and what was written to disk; check the "
            "parent process that issued the command."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or not process.cmdline:
            return None
        patterns = LOLBIN_PATTERNS.get(process.name.lower())
        if not patterns:
            return None
        text = " ".join(process.cmdline).lower()
        matches = [p for p in patterns if p.pattern.search(text)]
        if not matches:
            return None
        evidence = [
            observed(
                "Command line",
                "cmdline",
                _truncate(" ".join(process.cmdline), MAX_COMMAND_EVIDENCE_CHARS),
            )
        ]
        evidence.extend(inferred(match.description) for match in matches)
        techniques = tuple(dict.fromkeys(t for m in matches for t in m.techniques))
        return self.result(
            process=process,
            evidence=evidence,
            detail=matches[0].description,
            event=event,
            mitre=("T1218", *techniques),
            dedup_key=",".join(m.description for m in matches),
        )
