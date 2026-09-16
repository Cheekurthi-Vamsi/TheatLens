"""Persistence / autostart collector (Phase 11/12).

Enumerates the common places a program arranges to run automatically:

* Registry ``Run``/``RunOnce`` keys (HKCU + HKLM, incl. WOW64) via ``winreg`` — HKCU always
  readable, HKLM readable by standard users.
* Startup folders (per-user + all-users) via the filesystem — readable.
* Scheduled tasks by parsing the task XML under ``%SystemRoot%\\System32\\Tasks`` — most tasks
  are ACL-restricted to admins, so this source is often empty without elevation.
* Auto-start services via ``psutil.win_service_iter`` — readable.

Why parse the task XML files directly instead of the Task Scheduler COM API? It needs no extra
dependency, is readable without elevation for most tasks, and exposes exactly what we want (the
action's executable and arguments). Its limitation: tasks whose folder ACL denies the user are
skipped (counted in ``unavailable_sources``).

Every source is wrapped so one failing source never blanks the others. This collector only
*reads*; it never modifies persistence (spec §15).
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Final
from xml.etree import ElementTree

from threatlens.core.models.persistence import (
    PersistenceItem,
    PersistenceKind,
    PersistenceSnapshot,
)
from threatlens.utils import windows
from threatlens.utils.time import utc_now

logger = logging.getLogger(__name__)

if sys.platform == "win32":
    import winreg

    _RUN_KEYS: Final = (
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    )
    _HIVE_NAMES: Final = {winreg.HKEY_CURRENT_USER: "HKCU", winreg.HKEY_LOCAL_MACHINE: "HKLM"}

_TASK_NS: Final = "{http://schemas.microsoft.com/windows/2004/02/mit/task}"
_AUTO_START_TYPES: Final = frozenset({"automatic", "auto"})


def _split_command(command: str) -> tuple[str | None, str | None]:
    """Return (executable, arguments) from a configured command line."""
    command = command.strip()
    if not command:
        return None, None
    try:
        argv = windows.split_command_line(command)
    except OSError:
        return None, None
    if not argv:
        return None, None
    arguments = " ".join(argv[1:]) or None
    return argv[0], arguments


@dataclass(frozen=True, slots=True)
class PersistenceCollectorOptions:
    include_services: bool = True
    include_tasks: bool = True


class PersistenceCollector:
    name: Final = "persistence_collector"

    def __init__(self, options: PersistenceCollectorOptions | None = None) -> None:
        self._options = options or PersistenceCollectorOptions()

    def collect(self) -> PersistenceSnapshot:
        items: list[PersistenceItem] = []
        unavailable: list[str] = []
        for label, source in self._sources():
            try:
                items.extend(source())
            except Exception as exc:  # one source must never break the rest
                unavailable.append(label)
                logger.debug("event=PERSISTENCE_SOURCE_FAILED source=%s error=%s", label, exc)
        return PersistenceSnapshot(
            timestamp=utc_now(), items=tuple(items), unavailable_sources=tuple(unavailable)
        )

    def _sources(self) -> list[tuple[str, Callable[[], Iterable[PersistenceItem]]]]:
        sources: list[tuple[str, Callable[[], Iterable[PersistenceItem]]]] = [
            ("registry", self._registry_items),
            ("startup", self._startup_items),
        ]
        if self._options.include_tasks:
            sources.append(("tasks", self._scheduled_tasks))
        if self._options.include_services:
            sources.append(("services", self._services))
        return sources

    # -- registry ---------------------------------------------------------------------------

    def _registry_items(self) -> Iterator[PersistenceItem]:
        if sys.platform != "win32":
            return
        for hive, subkey in _RUN_KEYS:
            location = f"{_HIVE_NAMES[hive]}\\{subkey}"
            try:
                with winreg.OpenKey(hive, subkey) as key:
                    values = self._enum_values(key)
            except FileNotFoundError:
                continue
            except OSError as exc:
                logger.debug("event=RUN_KEY_DENIED key=%s error=%s", location, exc)
                continue
            for name, data in values:
                exe, args = _split_command(str(data))
                yield PersistenceItem(
                    kind=PersistenceKind.REGISTRY_RUN,
                    location=location,
                    name=name,
                    command=str(data),
                    executable=exe,
                    arguments=args,
                )

    @staticmethod
    def _enum_values(key: object) -> list[tuple[str, object]]:
        values: list[tuple[str, object]] = []
        index = 0
        while True:
            try:
                name, data, _type = winreg.EnumValue(key, index)  # type: ignore[arg-type]
            except OSError:
                break
            values.append((name, data))
            index += 1
        return values

    # -- startup folders --------------------------------------------------------------------

    def _startup_folders(self) -> Iterable[tuple[str, Path]]:
        appdata = os.environ.get("APPDATA")
        program_data = os.environ.get("PROGRAMDATA")
        if appdata:
            yield "per-user", Path(appdata) / r"Microsoft\Windows\Start Menu\Programs\Startup"
        if program_data:
            yield "all-users", Path(program_data) / r"Microsoft\Windows\Start Menu\Programs\Startup"

    def _startup_items(self) -> Iterator[PersistenceItem]:
        for _scope, folder in self._startup_folders():
            if not folder.is_dir():
                continue
            for entry in folder.iterdir():
                if entry.name.lower() == "desktop.ini" or entry.is_dir():
                    continue
                yield PersistenceItem(
                    kind=PersistenceKind.STARTUP_FOLDER,
                    location=str(folder),
                    name=entry.name,
                    command=str(entry),
                    executable=str(entry) if entry.suffix.lower() != ".lnk" else None,
                )

    # -- scheduled tasks --------------------------------------------------------------------

    def _scheduled_tasks(self) -> Iterator[PersistenceItem]:
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        tasks_root = Path(system_root) / "System32" / "Tasks"
        if not tasks_root.is_dir():
            return
        for path in tasks_root.rglob("*"):
            if not path.is_file():
                continue
            item = self._parse_task(path, tasks_root)
            if item is not None:
                yield item

    def _parse_task(self, path: Path, root: Path) -> PersistenceItem | None:
        try:
            tree = ElementTree.parse(path)  # noqa: S314 - local task files, not untrusted network XML
        except (ElementTree.ParseError, OSError):
            return None
        root_el = tree.getroot()
        exec_el = root_el.find(f".//{_TASK_NS}Actions/{_TASK_NS}Exec")
        if exec_el is None:
            return None  # non-Exec actions (COM handler, e-mail) are not our concern
        command = exec_el.findtext(f"{_TASK_NS}Command")
        arguments = exec_el.findtext(f"{_TASK_NS}Arguments")
        enabled_text = root_el.findtext(f".//{_TASK_NS}Settings/{_TASK_NS}Enabled")
        task_name = "\\" + str(path.relative_to(root)).replace("/", "\\")
        return PersistenceItem(
            kind=PersistenceKind.SCHEDULED_TASK,
            location="Task Scheduler",
            name=task_name,
            command=(command or "").strip() or None,
            executable=(command or "").strip() or None,
            arguments=(arguments or "").strip() or None,
            enabled=enabled_text is None or enabled_text.strip().lower() != "false",
        )

    # -- services ---------------------------------------------------------------------------

    def _services(self) -> Iterator[PersistenceItem]:
        if sys.platform != "win32":
            return
        import psutil

        for service in psutil.win_service_iter():
            try:
                info = service.as_dict()
            except (psutil.Error, OSError):
                continue
            start_type = str(info.get("start_type") or "").lower()
            if not any(auto in start_type for auto in _AUTO_START_TYPES):
                continue  # only auto-start services are persistence
            binpath = str(info.get("binpath") or "")
            exe, args = _split_command(binpath)
            yield PersistenceItem(
                kind=PersistenceKind.SERVICE,
                location=f"service:{info.get('name')}",
                name=str(info.get("display_name") or info.get("name") or "?"),
                command=binpath or None,
                executable=exe,
                arguments=args,
                enabled=str(info.get("status") or "").lower() != "stopped",
            )
