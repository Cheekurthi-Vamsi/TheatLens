"""Persistence and autostart models (Phase 11/12)."""

from __future__ import annotations

from enum import StrEnum

from pydantic import AwareDatetime, Field, computed_field

from threatlens.core.models.common import Frozen
from threatlens.utils.time import utc_now


class PersistenceKind(StrEnum):
    REGISTRY_RUN = "REGISTRY_RUN"
    STARTUP_FOLDER = "STARTUP_FOLDER"
    SCHEDULED_TASK = "SCHEDULED_TASK"
    SERVICE = "SERVICE"


class PersistenceItem(Frozen):
    """One autostart / persistence entry as observed on disk or in the registry.

    ``item_key`` is a stable identity so the monitor can tell a *new* entry from one already
    present, and the baseline can record what was there at capture time.
    """

    kind: PersistenceKind
    location: str  # registry path, folder, task path, or "service:<name>"
    name: str
    command: str | None = None  # the raw command line as configured
    executable: str | None = None  # resolved executable path, if extractable
    arguments: str | None = None
    enabled: bool = True
    observed_at: AwareDatetime = Field(default_factory=utc_now)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def item_key(self) -> str:
        return f"{self.kind.value}|{self.location}|{self.name}".lower()


class PersistenceSnapshot(Frozen):
    timestamp: AwareDatetime
    items: tuple[PersistenceItem, ...]
    unavailable_sources: tuple[str, ...] = ()

    def by_key(self) -> dict[str, PersistenceItem]:
        return {i.item_key: i for i in self.items}
