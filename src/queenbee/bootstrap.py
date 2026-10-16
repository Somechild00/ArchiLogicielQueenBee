"""Racine de composition : le seul endroit qui connaît tous les adaptateurs (plus de Singleton).

`QueenBee` est la Façade : une seule porte d'entrée, une seule vérification, rejets comptés.
"""

from __future__ import annotations

import os
from collections.abc import Iterable, Mapping
from pathlib import Path

from queenbee.adapters.inbound.log_parser import parse_sshd_line, read_lines
from queenbee.application.ports import Notifier
from queenbee.application.services import DetectionService, IncidentService
from queenbee.config import Settings, read_env_file, settings_from_env
from queenbee.domain.model import DomainError, Incident, SecurityEvent
from queenbee.domain.rules import RuleSet
from queenbee.factories import ComponentFactory, ProdFactory


class QueenBee:
    """Façade : ingère des lignes brutes ; une ligne refusée est comptée, jamais ignorée."""

    def __init__(self, detection: DetectionService, incidents: IncidentService) -> None:
        self.detection = detection
        self.incidents = incidents
        self.rejected = 0

    def ingest_lines(self, lines: Iterable[str]) -> list[Incident]:
        events: list[SecurityEvent] = []
        for line in lines:
            try:
                events.append(parse_sshd_line(line))
            except DomainError:
                self.rejected += 1
        return self.detection.ingest(events)


def build_app(settings: Settings, factory: ComponentFactory | None = None) -> QueenBee:
    """Assemble l'application. Chaque appel crée de nouveaux objets : aucun état global."""
    notifiers: list[Notifier] = []
    if factory is None:
        factory = ProdFactory(settings.db_path, settings.smtp)
        if settings.smtp is not None:
            notifiers.append(factory.notifier())
    else:
        notifiers.append(factory.notifier())
    repository = factory.repository()
    detection = DetectionService(RuleSet(settings.rules), repository, notifiers)
    return QueenBee(detection, IncidentService(repository))


def main(log_path: str, env: Mapping[str, str] | None = None) -> int:
    merged = {**read_env_file(Path(".env")), **(env if env is not None else os.environ)}
    app = build_app(settings_from_env(merged))
    incidents = app.ingest_lines(read_lines(Path(log_path)))
    print(f"{len(incidents)} incident(s) ouvert(s), {app.rejected} ligne(s) rejetée(s)")
    return 0
