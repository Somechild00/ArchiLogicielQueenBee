"""Ports : ce dont le centre a besoin, exprimé sans aucune technologie."""

from __future__ import annotations

from typing import Protocol
from uuid import UUID

from queenbee.domain.model import Alert, Incident


class IncidentReader(Protocol):
    def get(self, incident_id: UUID) -> Incident | None: ...
    def list_open(self) -> list[Incident]: ...


class IncidentRepository(IncidentReader, Protocol):
    def save(self, incident: Incident) -> None: ...


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...


class Firewall(Protocol):
    def block(self, ip: str) -> None: ...
    def unblock(self, ip: str) -> None: ...
