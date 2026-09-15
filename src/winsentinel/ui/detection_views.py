"""Rendering for detections and the rule catalog.

Wording rule (spec §42): detections are "suspicious", "unusual" or "requires investigation" —
never "malware". Every piece of evidence shows whether it was observed or inferred.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from winsentinel.core.models import (
    Confidence,
    DetectionResult,
    Observation,
    RuleMetadata,
    severity_for_score,
)
from winsentinel.ui import colors
from winsentinel.ui.formatting import sanitize_display
from winsentinel.utils.time import format_clock

CONFIDENCE_STYLES: dict[Confidence, str] = {
    Confidence.LOW: colors.MUTED,
    Confidence.MEDIUM: "yellow",
    Confidence.HIGH: "bold dark_orange",
}
_OBSERVATION_LABELS: dict[Observation, str] = {
    Observation.OBSERVED: "observed",
    Observation.INFERRED: "inferred",
    Observation.SUSPICIOUS: "suspicious",
    Observation.CONFIRMED: "confirmed",
}


def _evidence_lines(result: DetectionResult, indent: str) -> Text:
    text = Text()
    for index, item in enumerate(result.evidence):
        if index:
            text.append("\n")
        text.append(f"{indent}• ", style=colors.MUTED)
        text.append(
            f"[{_OBSERVATION_LABELS[item.observation]}] ",
            style="cyan" if item.observation is Observation.OBSERVED else "magenta",
        )
        text.append(sanitize_display(item.description))
        if item.value:
            text.append(f": {sanitize_display(item.value)}", style=colors.MUTED)
    return text


def detection_stream_text(result: DetectionResult) -> Text:
    """Multi-line block for ``monitor``: header, subject, evidence."""
    text = Text(format_clock(result.timestamp), style=colors.MUTED)
    text.append("  ")
    text.append("SUSPICIOUS".ljust(20), style="bold red")
    text.append(f"{result.rule_id}  ", style="bold")
    text.append(sanitize_display(result.rule_name))
    text.append(
        f"  score +{result.score}", style=colors.SEVERITY_STYLES[severity_for_score(result.score)]
    )
    text.append(
        f" · {result.confidence.value} confidence", style=CONFIDENCE_STYLES[result.confidence]
    )
    text.append("\n")
    text.append(" " * 14 + sanitize_display(result.summary), style="bold")
    if result.exe:
        text.append(f"\n{' ' * 14}{sanitize_display(result.exe)}", style=colors.MUTED)
    text.append("\n")
    text.append_text(_evidence_lines(result, " " * 14))
    return text


def detections_section(
    results: Sequence[DetectionResult], catalog: dict[str, RuleMetadata]
) -> RenderableType:
    """``inspect`` section: what, why, evidence, and what to do."""
    if not results:
        return Text(
            "No rule matched this process's current state. Behaviour over time (new listeners, "
            "bursts, first-seen communication) is evaluated by 'winsentinel monitor'.",
            style=colors.MUTED,
        )
    blocks: list[RenderableType] = []
    for result in sorted(results, key=lambda r: -r.score):
        header = Text()
        header.append(f"{result.rule_id}  ", style="bold")
        header.append(sanitize_display(result.rule_name), style="bold")
        header.append(
            f"   +{result.score}", style=colors.SEVERITY_STYLES[severity_for_score(result.score)]
        )
        header.append(
            f" · {result.confidence.value} confidence", style=CONFIDENCE_STYLES[result.confidence]
        )
        blocks.append(header)
        meta = catalog.get(result.rule_id)
        if meta is not None:
            blocks.append(Text("  Why it matters: " + meta.rationale, style=colors.MUTED))
        blocks.append(_evidence_lines(result, "  "))
        if meta is not None:
            blocks.append(Text("  What you can do: " + meta.recommendation, style="green"))
        if result.mitre_techniques:
            blocks.append(
                Text("  MITRE ATT&CK: " + ", ".join(result.mitre_techniques), style=colors.MUTED)
            )
        blocks.append(Text(""))
    blocks.append(
        Text(
            "These are signals that require investigation, not a verdict. Combined risk scoring "
            "arrives with alerts in a later phase.",
            style=colors.MUTED,
        )
    )
    return Group(*blocks)


def rules_table(rules: Sequence[RuleMetadata], disabled: Collection[str]) -> Table:
    table = Table(header_style=colors.HEADER, box=None, pad_edge=False)
    table.add_column("RULE", no_wrap=True, style="bold")
    table.add_column("NAME", overflow="fold", ratio=1)
    table.add_column("CATEGORY", no_wrap=True)
    table.add_column("SCORE", justify="right", no_wrap=True)
    table.add_column("CONFIDENCE", no_wrap=True)
    table.add_column("STATUS", no_wrap=True)
    for meta in rules:
        enabled = meta.rule_id not in disabled and meta.enabled_by_default
        table.add_row(
            meta.rule_id,
            meta.name,
            meta.category.value,
            f"+{meta.base_score}",
            Text(meta.confidence.value, style=CONFIDENCE_STYLES[meta.confidence]),
            Text("enabled", style="green") if enabled else Text("disabled", style=colors.MUTED),
        )
    return table


def rule_detail(meta: RuleMetadata, *, enabled: bool) -> RenderableType:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    grid.add_row("Rule", Text(f"{meta.rule_id}  {meta.name}", style="bold"))
    grid.add_row(
        "Status",
        Text("enabled", style="green") if enabled else Text("disabled", style=colors.MUTED),
    )
    grid.add_row("Category", meta.category.value)
    grid.add_row("Detects", meta.description)
    grid.add_row("Why", meta.rationale)
    grid.add_row("Evaluated on", ", ".join(t.value for t in meta.event_types))
    grid.add_row(
        "Score",
        f"up to +{meta.base_score} (alone: {meta.default_severity.value}) · "
        f"{meta.confidence.value} confidence",
    )
    grid.add_row("MITRE ATT&CK", ", ".join(meta.mitre_techniques) or "-")
    grid.add_row("False positives", "\n".join(f"• {item}" for item in meta.false_positives))
    grid.add_row("Recommendation", meta.recommendation)
    grid.add_row("Tuning", f'disable with detection.disabled_rules = ["{meta.rule_id}"]')
    return Panel(grid, title="DETECTION RULE", title_align="left", border_style="cyan")
