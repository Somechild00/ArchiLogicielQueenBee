"""Autorisation + Procuration (Proxy) de lecture. Même interface que l'objet protégé."""

from __future__ import annotations

from uuid import UUID

from queenbee.application.errors import AccessDeniedError
from queenbee.application.ports import IncidentReader
from queenbee.domain.model import Incident, Principal

READ_ROLES = frozenset({"viewer", "analyst"})
WRITE_ROLES = frozenset({"analyst"})


def require_role(principal: Principal, allowed: frozenset[str]) -> None:
    if not principal.roles & allowed:
        raise AccessDeniedError("access denied")


class IncidentReadProxy:
    """Lecture seule : n'expose volontairement ni save ni aucune écriture."""

    def __init__(self, target: IncidentReader, principal: Principal) -> None:
        self._target = target
        self._principal = principal
        self.denied = 0

    def _guard(self) -> None:
        try:
            require_role(self._principal, READ_ROLES)
        except AccessDeniedError:
            self.denied += 1
            raise

    def get(self, incident_id: UUID) -> Incident | None:
        self._guard()
        return self._target.get(incident_id)

    def list_open(self) -> list[Incident]:
        self._guard()
        return self._target.list_open()
