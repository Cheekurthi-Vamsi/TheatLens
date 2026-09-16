"""Regenerate docs/detection-rules.md from the rule metadata in code.

Usage:  python scripts/generate_rule_docs.py
The unit test ``test_rule_docs_are_current`` fails if the file is out of date.
"""

from __future__ import annotations

import sys
from pathlib import Path

from threatlens.config import Config
from threatlens.core.models import RuleMetadata
from threatlens.detection.rules import rule_catalog

HEADER = """\
# Detection Rules

> Generated from the rule metadata in `src/threatlens/detection/rules/` by
> `scripts/generate_rule_docs.py`. Do not edit by hand.

## How to read a detection

ThreatLens rules produce **signals, not verdicts**. Each detection carries:

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

`threatlens inspect <PID>` replays the *current state* of one process through the rules.
Rules that watch change over time (NET-001, NET-002, NET-003) only fire under
`threatlens monitor`.

## Rule summary

| Rule | Name | Category | Score | Confidence |
|------|------|----------|------:|------------|
"""

FOOTER_TEMPLATE = """
## Tuning

```toml
[detection]
disabled_rules = ["NET-004"]                       # turn rules off
ignored_executables = ['C:\\\\Tools\\\\scanner.exe']   # suppress by full path (never by name)
correlation_window_seconds = {window}              # PROC-004
network_burst_window_seconds = {burst_window}      # NET-003
network_burst_threshold = {burst}
network_fanout_threshold = {fanout}
failed_connection_threshold = {failed}
common_remote_ports = [{ports}]                    # NET-004
trusted_paths = [{trusted}]
```

Trusted paths reduce noise but are not blind spots: masquerading (PROC-005), deceptive names
(PROC-008), invalid signatures (SIG-001), suspicious lineage and command lines still apply there,
and user-writable folders *inside* trusted paths (e.g. `C:\\Windows\\System32\\spool\\drivers\\color`)
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
"""


def rule_section(meta: RuleMetadata) -> str:
    events = ", ".join(f"`{e.value}`" for e in meta.event_types)
    mitre = ", ".join(meta.mitre_techniques) or "-"
    false_positives = "\n".join(f"* {item}" for item in meta.false_positives)
    return (
        f"\n### {meta.rule_id} — {meta.name}\n\n"
        f"**Detects:** {meta.description}\n\n"
        f"**Why it matters:** {meta.rationale}\n\n"
        f"| Category | Score | Confidence | Alone | Evaluated on | MITRE ATT&CK |\n"
        f"|----------|------:|------------|-------|--------------|--------------|\n"
        f"| {meta.category.value} | +{meta.base_score} | {meta.confidence.value} | "
        f"{meta.default_severity.value} | {events} | {mitre} |\n\n"
        f"**Known false positives:**\n\n{false_positives}\n\n"
        f"**What to do:** {meta.recommendation}\n"
    )


def render() -> str:
    catalog = rule_catalog()
    detection = Config().detection
    summary = "".join(
        f"| [{m.rule_id}](#{m.rule_id.lower()}--{_anchor(m.name)}) | {m.name} | {m.category.value} "
        f"| +{m.base_score} | {m.confidence.value} |\n"
        for m in catalog
    )
    footer = FOOTER_TEMPLATE.format(
        window=detection.correlation_window_seconds,
        burst_window=detection.network_burst_window_seconds,
        burst=detection.network_burst_threshold,
        fanout=detection.network_fanout_threshold,
        failed=detection.failed_connection_threshold,
        ports=", ".join(map(str, detection.common_remote_ports)),
        trusted=", ".join(f"'{p}'" for p in detection.trusted_paths),
    )
    return HEADER + summary + "\n## Rules\n" + "".join(rule_section(m) for m in catalog) + footer


def _anchor(name: str) -> str:
    return "".join(c for c in name.lower().replace(" ", "-") if c.isalnum() or c == "-")


def main() -> int:
    target = Path(__file__).resolve().parent.parent / "docs" / "detection-rules.md"
    target.write_text(render(), encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
