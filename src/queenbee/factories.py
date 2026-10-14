"""Abstract Factory : deux familles cohérentes de composants (production / mémoire)."""

from __future__ import annotations

from typing import Protocol

from queenbee.adapters.outbound.notifiers import MemoryNotifier, SmtpNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.config import ConfigError, SmtpSettings
from queenbee.domain.ports import IncidentRepository, Notifier


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
    """Famille « production » : SQLite + SMTP. Les secrets arrivent par les réglages."""

    def __init__(self, db_path: str, smtp: SmtpSettings | None = None) -> None:
        self._db_path = db_path
        self._smtp = smtp

    def repository(self) -> SqliteIncidentRepository:
        return SqliteIncidentRepository(self._db_path)

    def notifier(self) -> SmtpNotifier:
        if self._smtp is None:
            raise ConfigError("SMTP non configuré")
        return SmtpNotifier(self._smtp)
