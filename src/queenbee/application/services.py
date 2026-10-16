"""Cas d'usage. Ordre imposé : autoriser -> vérifier -> règle métier -> persister."""

from __future__ import annotations

from collections.abc import Sequence
from uuid import UUID

from queenbee.application.access import WRITE_ROLES, require_role
from queenbee.application.errors import AccessDeniedError
from queenbee.application.ports import IncidentRepository, Notifier
from queenbee.domain.model import DomainError, Incident, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import Rule

__all__ = ["AccessDeniedError", "DetectionService", "IncidentService"]


class DetectionService:
    def __init__(self, rule: Rule, repo: IncidentRepository, notifiers: Sequence[Notifier]) -> None:
        self._rule, self._repo, self._notifiers = rule, repo, tuple(notifiers)

    def ingest(self, events: Sequence[SecurityEvent]) -> list[Incident]:
        created: list[Incident] = []
        for alert in self._rule.evaluate(events):
            incident = Incident(alert)
            self._repo.save(incident)
            for notifier in self._notifiers:
                notifier.notify(alert)
            created.append(incident)
        return created


class IncidentService:
    def __init__(self, repo: IncidentRepository) -> None:
        self._repo = repo
        self.denied = 0

    def move(self, principal: Principal, incident_id: UUID, target: IncidentStatus) -> Incident:
        try:
            require_role(principal, WRITE_ROLES)  # 1. autoriser
        except AccessDeniedError:
            self.denied += 1
            raise
        incident = self._repo.get(incident_id)  # 2. vérifier
        if incident is None:
            raise DomainError("unknown incident")
        incident.transition_to(target)  # 3. règle métier
        self._repo.save(incident)  # 4. persister
        return incident
