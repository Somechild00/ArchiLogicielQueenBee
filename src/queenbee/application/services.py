"""Cas d'usage : détecter, enregistrer, notifier. Dépend uniquement des ports du domaine."""

from __future__ import annotations

from collections.abc import Sequence

from queenbee.domain.model import Alert, Incident, SecurityEvent
from queenbee.domain.ports import IncidentRepository, Notifier
from queenbee.domain.rules import Rule


class DetectionService:
    def __init__(
        self, rule: Rule, repository: IncidentRepository, notifiers: Sequence[Notifier]
    ) -> None:
        self._rule = rule
        self._repository = repository
        self._notifiers = tuple(notifiers)

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        alerts = self._rule.evaluate(events)
        for alert in alerts:
            self._repository.add(Incident(alert))
            for notifier in self._notifiers:
                notifier.notify(alert)
        return alerts
