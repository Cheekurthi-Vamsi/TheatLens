"""Allowlist: mark known-good activity so it stops generating detections.

Matching is by **stable characteristics**, strongest first (spec §28):

* ``SHA256`` — the file's content. Strongest: a different file with the same name does not match.
* ``SIGNER`` — the valid-signature publisher. Trusts everything that publisher signs.
* ``EXE_PATH`` — the full path. Weaker (a path can be reused) but the common, understandable case.

Matching on a bare process *name* is deliberately unsupported: a name is trivially spoofed by
copying a file, so allowlisting ``chrome.exe`` by name would let malware named ``chrome.exe``
inherit the exemption. The CLI explains this when a user tries.

An entry may scope to specific ``rule_ids``; otherwise it suppresses every rule for that program.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from winsentinel.core.models import ProcessInfo, SignatureStatus
from winsentinel.detection.paths import normalize
from winsentinel.utils.time import utc_now


class AllowlistMatchType(StrEnum):
    EXE_PATH = "EXE_PATH"
    SHA256 = "SHA256"
    SIGNER = "SIGNER"


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    match_type: AllowlistMatchType
    value: str
    rule_ids: tuple[str, ...] = ()  # empty = all rules
    reason: str = ""
    expires_at: datetime | None = None

    def canonical_value(self) -> str:
        if self.match_type is AllowlistMatchType.EXE_PATH:
            return normalize(self.value)
        if self.match_type is AllowlistMatchType.SHA256:
            return self.value.lower()
        return self.value

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and now >= self.expires_at


def entry_from_row(row: Any) -> AllowlistEntry:
    return AllowlistEntry(
        match_type=AllowlistMatchType(row["match_type"]),
        value=row["value"],
        rule_ids=tuple(r for r in (row["rule_ids"] or "").split(",") if r),
        reason=row["reason"] or "",
        expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
    )


class AllowlistMatcher:
    """Immutable snapshot of active allowlist entries with fast lookup."""

    def __init__(self, entries: Sequence[AllowlistEntry], *, now: datetime | None = None) -> None:
        moment = now or utc_now()
        active = [e for e in entries if not e.is_expired(moment)]
        self._by_path = {
            e.canonical_value(): e for e in active if e.match_type is AllowlistMatchType.EXE_PATH
        }
        self._by_sha = {
            e.canonical_value(): e for e in active if e.match_type is AllowlistMatchType.SHA256
        }
        self._by_signer = {
            e.canonical_value(): e for e in active if e.match_type is AllowlistMatchType.SIGNER
        }

    def match(self, process: ProcessInfo, rule_id: str) -> AllowlistEntry | None:
        candidates: list[AllowlistEntry | None] = []
        if process.sha256:
            candidates.append(self._by_sha.get(process.sha256.lower()))
        if (
            process.signature is not None
            and process.signature.status is SignatureStatus.VALID
            and process.signature.signer
        ):
            candidates.append(self._by_signer.get(process.signature.signer))
        if process.exe:
            candidates.append(self._by_path.get(normalize(process.exe)))
        for entry in candidates:
            if entry is not None and (not entry.rule_ids or rule_id in entry.rule_ids):
                return entry
        return None

    def allows(self, process: ProcessInfo, rule_id: str) -> bool:
        return self.match(process, rule_id) is not None

    def __len__(self) -> int:
        return len(self._by_path) + len(self._by_sha) + len(self._by_signer)
