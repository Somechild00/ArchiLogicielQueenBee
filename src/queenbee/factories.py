"""Fabrique abstraite : deux familles cohérentes de composants (production / mémoire)."""

from __future__ import annotations

import sqlite3
from typing import Protocol

from queenbee.adapters.outbound.notifiers import (
    AuditedNotifier,
    MemoryNotifier,
    RateLimitedNotifier,
    SmtpNotifier,
)
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.config import ConfigError, SmtpSettings

ALERTS_PER_WINDOW = 30
WINDOW_S = 60.0


class ComponentFactory(Protocol):
    def repository(self) -> IncidentRepository: ...

    def notifier(self) -> Notifier: ...


class InMemoryFactory:
    """Famille « mémoire » : rien ne sort du processus (tests, démonstrations)."""

    def repository(self) -> InMemoryIncidentRepository:
        return InMemoryIncidentRepository()

    def notifier(self) -> MemoryNotifier:
        return MemoryNotifier()


class ProdFactory:
    """Famille « production » : SQLite + SMTP audité et limité ; secrets venus des réglages."""

    def __init__(self, db_path: str, smtp: SmtpSettings | None = None) -> None:
        self._db_path = db_path
        self._smtp = smtp

    def repository(self) -> SqliteIncidentRepository:
        return SqliteIncidentRepository(sqlite3.connect(self._db_path))

    def notifier(self) -> Notifier:
        if self._smtp is None:
            raise ConfigError("SMTP non configuré")
        return AuditedNotifier(
            RateLimitedNotifier(SmtpNotifier(self._smtp), ALERTS_PER_WINDOW, WINDOW_S)
        )
