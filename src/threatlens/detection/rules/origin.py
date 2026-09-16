"""Rules about an executable's location, signature and name."""

from __future__ import annotations

import ntpath
import re
from typing import Final

from threatlens.core.interfaces import StateView
from threatlens.core.models import (
    Confidence,
    DetectionResult,
    EventType,
    RuleCategory,
    RuleMetadata,
    SecurityEvent,
    SignatureStatus,
)
from threatlens.detection.catalog import (
    ALWAYS_ALLOWED_SYSTEM_SUBDIRS,
    DOCUMENT_EXTENSIONS,
    EXECUTABLE_EXTENSIONS,
    SYSTEM_BINARY_LOCATIONS,
)
from threatlens.detection.paths import is_under
from threatlens.detection.rules.base import Rule, inferred, observed
from threatlens.security.signatures import CERT_E_EXPIRED, TRUST_E_BAD_DIGEST

PROCESS_APPEARANCE: Final = (EventType.PROCESS_STARTED, EventType.PROCESS_DISCOVERED)


class TempDirectoryExecution(Rule):
    meta = RuleMetadata(
        rule_id="PROC-001",
        name="Executable running from a temporary directory",
        description="A process's executable image is located in a temporary directory.",
        rationale=(
            "Temporary directories are writable by every user; droppers, downloaders and exploit "
            "payloads commonly write their next stage there and run it. Legitimate applications "
            "install to Program Files, but installers and updaters also unpack to Temp, so this "
            "signal is weak on its own."
        ),
        category=RuleCategory.ORIGIN,
        event_types=PROCESS_APPEARANCE,
        base_score=20,
        confidence=Confidence.MEDIUM,
        mitre_techniques=("T1204.002",),
        false_positives=(
            "Installers and updaters that extract themselves to %TEMP% before running",
            "Programs started directly from inside a ZIP archive (Explorer extracts them to Temp)",
        ),
        recommendation=(
            "Check the parent process and the file's signature and publisher. Confirm whether the "
            "user knowingly ran an installer or opened an archive."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.exe is None:
            return None
        location = self.settings.paths.temp_location(process.exe)
        if location is None:
            return None
        evidence = [observed(f"Executable image is in {location}", "exe", process.exe)]
        parent = state.parent_of(process)
        if parent is not None:
            evidence.append(
                observed(
                    f"Started by {parent.name} (PID {parent.pid})",
                    "parent",
                    parent.exe or parent.name,
                )
            )
        return self.result(
            process=process, evidence=evidence, detail=f"running from {location}", event=event
        )


class UnsignedUserWritableExecutable(Rule):
    meta = RuleMetadata(
        rule_id="PROC-002",
        name="Unsigned executable in a user-writable location",
        description=(
            "An executable without any Authenticode signature runs from a location standard users "
            "can write to."
        ),
        rationale=(
            "Code in user-writable locations can be planted without administrator rights, and "
            "an absent signature means there is no verifiable publisher. Plenty of legitimate "
            "tools are unsigned, so this is a low-confidence signal that gains weight only in "
            "combination with others."
        ),
        category=RuleCategory.SIGNATURE,
        event_types=(EventType.PROCESS_ENRICHED,),
        base_score=15,
        confidence=Confidence.LOW,
        mitre_techniques=("T1204.002",),
        false_positives=(
            "Unsigned developer tools, scripts compiled locally, portable utilities",
            "Per-user installs of small open-source applications",
        ),
        recommendation=(
            "Look up the SHA256 in your threat-intelligence source of choice, and confirm the "
            "program is expected on this machine. Allowlist it by path or hash if it is."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.exe is None or process.signature is None:
            return None
        if process.signature.status is not SignatureStatus.UNSIGNED:
            return None
        paths = self.settings.paths
        location = paths.user_writable_location(process.exe)
        if location is None or paths.is_trusted(process.exe):
            return None
        evidence = [
            observed("No embedded or catalog Authenticode signature", "signature", "UNSIGNED"),
            inferred(
                f"Located in {location} (writable without administrator rights by default)",
                "exe",
                process.exe,
            ),
        ]
        if process.sha256:
            evidence.append(observed("File hash", "sha256", process.sha256))
        return self.result(
            process=process,
            evidence=evidence,
            detail="unsigned executable in a user-writable location",
            event=event,
        )


class InvalidSignature(Rule):
    meta = RuleMetadata(
        rule_id="SIG-001",
        name="Invalid executable signature",
        description="An executable carries an Authenticode signature that fails verification.",
        rationale=(
            "A signature that exists but does not verify means the file changed after signing "
            "(tampering or patching) or the certificate chain is untrusted, explicitly "
            "distrusted or expired. A tampered signed binary is a classic way to borrow a "
            "trusted publisher's reputation."
        ),
        category=RuleCategory.SIGNATURE,
        event_types=(EventType.PROCESS_ENRICHED,),
        base_score=45,
        confidence=Confidence.HIGH,
        mitre_techniques=("T1553.002", "T1036.001"),
        false_positives=(
            "Old software signed with a certificate that expired without a timestamp (scored +10 "
            "LOW; "
            "e.g. Git for Windows' usr\\bin\\bash.exe)",
            "Software patched or cracked locally by the user",
        ),
        recommendation=(
            "Compare the file hash with the vendor's official release. If the digest does not "
            "match, treat the file as untrusted until its origin is explained."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.signature is None:
            return None
        signature = process.signature
        if signature.status is not SignatureStatus.INVALID:
            return None
        error = None if signature.error_code is None else signature.error_code & 0xFFFFFFFF
        code = None if error is None else f"0x{error:08X}"
        evidence = [
            observed(
                f"Authenticode verification failed: {signature.detail or 'untrusted signature'}",
                "signature_error",
                code,
            )
        ]
        if error == TRUST_E_BAD_DIGEST:
            evidence.append(
                inferred(
                    "The file's contents do not match the signed digest: it was modified after "
                    "signing"
                )
            )
            score, confidence, detail = (
                45,
                Confidence.HIGH,
                "signature invalid: file modified after signing",
            )
        elif error == CERT_E_EXPIRED:
            evidence.append(
                inferred(
                    "An expired certificate without a timestamp is typical of older legitimate "
                    "software; weak evidence on its own"
                )
            )
            score, confidence, detail = (
                10,
                Confidence.LOW,
                "signing certificate expired (no timestamp)",
            )
        else:
            evidence.append(
                inferred(
                    "A signature exists but does not chain to a certificate trusted on this machine"
                )
            )
            score, confidence, detail = 30, Confidence.MEDIUM, "signature present but not trusted"
        return self.result(
            process=process,
            evidence=evidence,
            detail=detail,
            event=event,
            score=score,
            confidence=confidence,
        )


class SystemBinaryMasquerading(Rule):
    meta = RuleMetadata(
        rule_id="PROC-005",
        name="Windows system binary name from an unexpected location",
        description=(
            "A process uses the name of a core Windows binary but runs from outside its "
            "legitimate directory."
        ),
        rationale=(
            "Malware names itself svchost.exe, lsass.exe or explorer.exe so it blends into process "
            "lists. The genuine binaries live only in specific Windows directories, which makes "
            "this check precise."
        ),
        category=RuleCategory.MASQUERADE,
        event_types=PROCESS_APPEARANCE,
        base_score=45,
        confidence=Confidence.HIGH,
        mitre_techniques=("T1036.005",),
        false_positives=(
            "Copies of system binaries made by backup, forensic or sandbox tools",
            "Software that ships its own helper with a coincidentally identical name",
        ),
        recommendation=(
            "Inspect the file's signature and hash immediately; genuine system binaries are "
            "Microsoft-signed and live under the Windows directory."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None or process.exe is None:
            return None
        name = process.name.lower()
        allowed = SYSTEM_BINARY_LOCATIONS.get(name)
        if allowed is None or ntpath.basename(process.exe).lower() != name:
            return None
        paths = self.settings.paths
        root = paths.system_root
        allowed_dirs = {f"{root}\\{d}".rstrip("\\") if d else root for d in allowed}
        directory = paths.directory_of(process.exe)
        if directory in allowed_dirs or any(
            is_under(process.exe, f"{root}\\{sub}") for sub in ALWAYS_ALLOWED_SYSTEM_SUBDIRS
        ):
            return None
        evidence = [
            observed(
                f"Process is named {process.name}, the name of a core Windows binary",
                "name",
                process.name,
            ),
            observed("Actual location", "exe", process.exe),
            inferred("The genuine binary runs only from: " + ", ".join(sorted(allowed_dirs))),
        ]
        return self.result(
            process=process,
            evidence=evidence,
            detail=f"{process.name} running from an unexpected directory",
            event=event,
        )


_BIDI_CONTROL: Final = re.compile("[؜‎‏‪-‮⁦-⁩]")
_DOUBLE_EXTENSION: Final = re.compile(
    rf"\.({'|'.join(DOCUMENT_EXTENSIONS)})\s*\.({'|'.join(EXECUTABLE_EXTENSIONS)})$", re.IGNORECASE
)
_PADDED_EXTENSION: Final = re.compile(r"\s{3,}\.(exe|scr|com|pif)$", re.IGNORECASE)


class DeceptiveFileName(Rule):
    meta = RuleMetadata(
        rule_id="PROC-008",
        name="Deceptive executable file name",
        description=(
            "An executable's name is crafted to look like a document: a double extension, padding "
            "before the extension, or a right-to-left override character."
        ),
        rationale=(
            "invoice.pdf.exe, 'report.docx      .exe' and names using U+202E (which renders "
            "'invoice‮txt.exe' as 'invoiceexe.txt') exist to trick a person into running a "
            "program they believe is a document. Legitimate software has no reason to do this."
        ),
        category=RuleCategory.MASQUERADE,
        event_types=PROCESS_APPEARANCE,
        base_score=40,
        confidence=Confidence.HIGH,
        mitre_techniques=("T1036.002", "T1036.007"),
        false_positives=(
            "Rare: automatically generated file names that happen to contain a dotted document "
            "extension",
        ),
        recommendation=(
            "Treat the program as untrusted; find where the file came from (download, e-mail "
            "attachment, USB)."
        ),
    )

    def evaluate(self, event: SecurityEvent, state: StateView) -> DetectionResult | None:
        process = self.subject(event, state)
        if process is None:
            return None
        names = {process.name}
        if process.exe:
            names.add(ntpath.basename(process.exe))
        evidence = []
        for name in sorted(names):
            if _BIDI_CONTROL.search(name):
                evidence.append(
                    observed(
                        "Name contains a Unicode bidirectional control character that reorders "
                        "how it is displayed",
                        "name",
                        ascii(name),
                    )
                )
            elif _DOUBLE_EXTENSION.search(name):
                evidence.append(
                    observed(
                        "Name has a document extension followed by an executable extension",
                        "name",
                        name,
                    )
                )
            elif _PADDED_EXTENSION.search(name):
                evidence.append(
                    observed(
                        "Name pads whitespace before the executable extension to hide it",
                        "name",
                        name,
                    )
                )
        if not evidence:
            return None
        return self.result(
            process=process,
            evidence=evidence,
            detail="executable name disguised as a document",
            event=event,
        )
