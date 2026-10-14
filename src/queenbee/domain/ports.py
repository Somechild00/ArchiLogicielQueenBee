"""Ports : contrats (typing.Protocol) que le domaine exige de l'extérieur.

Le domaine ne connaît ni sqlite3 ni smtplib : les adaptateurs implémentent ces contrats.
"""

from __future__ import annotations

from typing import Protocol

from queenbee.domain.model import Alert, Incident


class IncidentRepository(Protocol):
    def add(self, incident: Incident) -> None: ...

    def all(self) -> list[Incident]: ...


class Notifier(Protocol):
    def notify(self, alert: Alert) -> None: ...
