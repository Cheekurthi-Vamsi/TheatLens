"""Rich renderables for processes: table, detail view, and tree."""

from __future__ import annotations

from collections.abc import Mapping, Sequence

from rich.console import Group, RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

from threatlens.core.models import ProcessInfo, ProcessNode, SignatureStatus
from threatlens.ui import colors
from threatlens.ui.formatting import (
    field_or_reason,
    format_bytes,
    format_percent,
    sanitize_display,
    truncate_middle,
)
from threatlens.utils.time import format_local

PATH_COLUMN_WIDTH = 60


def _safe(value: str, style: str = "") -> Text:
    """The only way untrusted strings become renderables in this module."""
    return Text(sanitize_display(value), style=style)


def _value(process: ProcessInfo, field: str, value: object | None, style: str = "") -> Text:
    text, placeholder = field_or_reason(process, field, value)
    return Text(text, style=colors.MUTED if placeholder else style)


def _signature_text(process: ProcessInfo) -> Text:
    if process.signature is None:
        return _value(process, "signature", None)
    status = process.signature.status
    return Text(status.value, style=colors.SIGNATURE_STYLES[status])


def process_table(processes: Sequence[ProcessInfo], *, show_signature: bool = False) -> Table:
    # Identity and numeric columns get fixed minimum widths so a narrow terminal truncates the
    # path (and then names) rather than silently dropping PIDs.
    table = Table(header_style=colors.HEADER, expand=False, pad_edge=False, box=None)
    table.add_column("PID", justify="right", style="bold", no_wrap=True, min_width=6)
    table.add_column("PPID", justify="right", style=colors.MUTED, no_wrap=True, min_width=6)
    table.add_column("NAME", no_wrap=True, min_width=12, max_width=32, overflow="ellipsis")
    table.add_column("USER", no_wrap=True, min_width=8, max_width=28, overflow="ellipsis")
    table.add_column("CPU%", justify="right", no_wrap=True, min_width=5)
    table.add_column("MEMORY", justify="right", no_wrap=True, min_width=8)
    table.add_column("THR", justify="right", style=colors.MUTED, no_wrap=True, min_width=3)
    table.add_column("INTEGRITY", no_wrap=True, min_width=9)
    if show_signature:
        table.add_column("SIGNATURE", no_wrap=True, min_width=9)
    table.add_column("PATH", no_wrap=True, overflow="ellipsis", ratio=1, min_width=10)

    for p in processes:
        row: list[RenderableType] = [
            Text(str(p.pid)),
            Text("-" if p.ppid is None else str(p.ppid)),
            _safe(p.name, style="red" if p.suspended else ""),
            _value(p, "username", p.username),
            Text(format_percent(p.cpu_percent)),
            Text(format_bytes(p.working_set)),
            Text("-" if p.num_threads is None else str(p.num_threads)),
            Text(p.integrity_level.value, style=colors.INTEGRITY_STYLES[p.integrity_level]),
        ]
        if show_signature:
            row.append(_signature_text(p))
        path_text, placeholder = field_or_reason(p, "exe", p.exe)
        row.append(
            Text(
                truncate_middle(path_text, PATH_COLUMN_WIDTH),
                style=colors.MUTED if placeholder else "",
            )
        )
        table.add_row(*row)
    return table


def _grid() -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=colors.LABEL, no_wrap=True)
    grid.add_column(overflow="fold")
    return grid


def _process_label(process: ProcessInfo) -> Text:
    label = _safe(process.name, style="bold")
    label.append(f"  (PID {process.pid})", style=colors.MUTED)
    return label


def process_detail(
    process: ProcessInfo,
    parents: Sequence[ProcessInfo],
    children: Sequence[ProcessInfo],
    *,
    parent_note: str | None = None,
    extra_sections: Sequence[tuple[str, RenderableType]] = (),
    title: str = "PROCESS",
) -> RenderableType:
    """Full detail panel for ``process <PID>``; ``inspect`` appends network and detections."""
    identity = _grid()
    identity.add_row("PID", Text(str(process.pid)))
    identity.add_row("Name", _safe(process.name))
    identity.add_row("Process key", Text(process.process_key, style=colors.MUTED))
    identity.add_row("User", _value(process, "username", process.username))
    identity.add_row("Created", Text(format_local(process.create_time)))
    identity.add_row(
        "Session", Text("-" if process.session_id is None else str(process.session_id))
    )
    identity.add_row(
        "Integrity",
        _value(
            process,
            "integrity_level",
            None if process.integrity_level.value == "UNKNOWN" else process.integrity_level.value,
            colors.INTEGRITY_STYLES[process.integrity_level],
        ),
    )
    identity.add_row(
        "Architecture",
        _value(
            process,
            "architecture",
            None if process.architecture.value == "UNKNOWN" else process.architecture.value,
        ),
    )
    identity.add_row(
        "State", Text("SUSPENDED", style="bold red") if process.suspended else Text("running")
    )

    image = _grid()
    image.add_row("Path", _value(process, "exe", process.exe))
    image.add_row("Command line", _value(process, "cmdline", process.command_line))
    image.add_row("SHA256", _value(process, "sha256", process.sha256))
    image.add_row("Signature", _signature_detail(process))

    resources = _grid()
    resources.add_row("CPU", Text(f"{format_percent(process.cpu_percent)} % of total capacity"))
    resources.add_row("Working set", Text(format_bytes(process.working_set)))
    resources.add_row("Private bytes", Text(format_bytes(process.private_bytes)))
    resources.add_row("Threads", Text(str(process.num_threads)))
    resources.add_row("Handles", Text(str(process.handle_count)))

    lineage = _grid()
    if parents:
        chain = Text()
        for index, ancestor in enumerate(reversed(parents)):
            if index:
                chain.append("  →  ", style=colors.MUTED)
            chain.append_text(_process_label(ancestor))
        chain.append("  →  ", style=colors.MUTED)
        chain.append_text(_safe(process.name, style="bold underline"))
        lineage.add_row("Ancestry", chain)
    else:
        lineage.add_row(
            "Ancestry", _safe(parent_note or "no verifiable parent", style=colors.MUTED)
        )
    if children:
        kids = Text()
        for index, child in enumerate(children):
            if index:
                kids.append("\n")
            kids.append_text(_process_label(child))
        lineage.add_row("Children", kids)
    else:
        lineage.add_row("Children", Text("none", style=colors.MUTED))

    sections: list[RenderableType] = []
    for heading, body in (
        ("IDENTITY", identity),
        ("IMAGE", image),
        ("RESOURCES", resources),
        ("LINEAGE", lineage),
        *extra_sections,
    ):
        sections.append(Text(heading, style="bold underline"))
        sections.append(body)
        sections.append(Text(""))
    return Panel(Group(*sections[:-1]), title=title, title_align="left", border_style="cyan")


def _signature_detail(process: ProcessInfo) -> Text:
    signature = process.signature
    if signature is None:
        return _value(process, "signature", None)
    text = Text(signature.status.value, style=colors.SIGNATURE_STYLES[signature.status])
    if signature.source.value != "NONE":
        text.append(f"  ({signature.source.value.lower()})", style=colors.MUTED)
    if signature.status is SignatureStatus.VALID and signature.signer:
        text.append("  signer: ")
        text.append_text(_safe(signature.signer, style="bold"))
    if signature.detail:
        text.append("\n")
        text.append_text(_safe(signature.detail, style=colors.MUTED))
    return text


def describe_unverified_parent(
    process: ProcessInfo, by_pid: Mapping[int, ProcessInfo]
) -> str | None:
    """Explain *why* a process has no verified parent (the reason matters when investigating)."""
    if process.ppid is None or process.ppid == 0:
        return None
    holder = by_pid.get(process.ppid)
    if holder is None:
        return f"parent PID {process.ppid} has exited"
    if holder.pid == process.pid:
        return None
    return (
        f"parent PID {process.ppid} has exited; that PID now belongs to a newer, unrelated "
        f"process ({holder.name})"
    )


def process_tree(
    roots: Sequence[ProcessNode], by_pid: Mapping[int, ProcessInfo], *, title: str = "Processes"
) -> Tree:
    tree = Tree(Text(title, style="bold"), guide_style=colors.MUTED)

    def label(node: ProcessNode) -> Text:
        p = node.process
        text = _safe(p.name, style="bold red" if p.suspended else "bold")
        text.append(f"  {p.pid}", style="cyan")
        if p.username:
            text.append_text(_safe(f"  {p.username}", style=colors.MUTED))
        if p.suspended:
            text.append("  [suspended]", style="red")
        if not node.parent_verified:
            note = describe_unverified_parent(p, by_pid)
            if note:
                text.append_text(_safe(f"  ({note})", style=colors.MUTED))
        return text

    def add(branch: Tree, node: ProcessNode) -> None:
        child_branch = branch.add(label(node))
        for child in node.children:
            add(child_branch, child)

    for root in roots:
        add(tree, root)
    return tree
