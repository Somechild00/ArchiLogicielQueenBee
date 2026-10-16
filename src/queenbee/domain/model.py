"""Modèle de domaine : objets valides dès leur construction, aucune I/O."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum, IntEnum
from uuid import UUID, uuid4


class DomainError(ValueError):
    """Règle métier ou de sécurité violée. Les messages ne reprennent jamais l'entrée brute."""


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class IncidentStatus(Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONTAINED = "contained"
    CLOSED = "closed"


ALLOWED_ACTIONS: frozenset[str] = frozenset({"login_failed", "login_ok", "logout", "port_probe"})
_USERNAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")
MAX_MESSAGE_LENGTH = 500


def _require_ip(value: object) -> str:
    if not isinstance(value, str):
        raise DomainError("adresse IP : une chaîne est attendue")
    try:
        ipaddress.ip_address(value)
    except ValueError as exc:
        raise DomainError("adresse IP invalide") from exc
    return value


@dataclass(frozen=True, slots=True)
class SecurityEvent:
    """Fait observé dans un journal. Immuable : un événement ne se corrige pas, il se remplace."""

    source_ip: str
    username: str
    action: str
    timestamp: datetime

    def __post_init__(self) -> None:
        _require_ip(self.source_ip)
        if not isinstance(self.username, str) or _USERNAME_RE.fullmatch(self.username) is None:
            raise DomainError("nom d'utilisateur invalide (caractères ou longueur)")
        if self.action not in ALLOWED_ACTIONS:
            raise DomainError("action hors liste autorisée")
        if (
            not isinstance(self.timestamp, datetime)
            or self.timestamp.tzinfo is None
            or self.timestamp.utcoffset() is None
        ):
            raise DomainError("horodatage sans fuseau horaire refusé")


@dataclass(frozen=True, slots=True)
class Alert:
    """Résultat d'une règle de détection."""

    rule: str
    source_ip: str
    severity: Severity
    message: str

    def __post_init__(self) -> None:
        if not isinstance(self.rule, str) or not self.rule:
            raise DomainError("nom de règle vide")
        _require_ip(self.source_ip)
        try:
            Severity(self.severity)
        except ValueError as exc:
            raise DomainError("sévérité invalide") from exc
        if not isinstance(self.message, str) or len(self.message) > MAX_MESSAGE_LENGTH:
            raise DomainError("message d'alerte invalide")


# Pattern État : la table des transitions autorisées. Tout le reste est interdit.
_TRANSITIONS: dict[IncidentStatus, frozenset[IncidentStatus]] = {
    IncidentStatus.OPEN: frozenset({IncidentStatus.TRIAGED}),
    IncidentStatus.TRIAGED: frozenset({IncidentStatus.CONTAINED, IncidentStatus.CLOSED}),
    IncidentStatus.CONTAINED: frozenset({IncidentStatus.CLOSED}),
    IncidentStatus.CLOSED: frozenset(),
}


@dataclass
class Incident:
    """Entité (elle a un id) : on ne ferme pas un incident sans l'avoir qualifié."""

    alert: Alert
    id: UUID = field(default_factory=uuid4)
    status: IncidentStatus = IncidentStatus.OPEN

    def transition_to(self, new_status: IncidentStatus) -> None:
        if new_status not in _TRANSITIONS[self.status]:
            raise DomainError(f"transition interdite : {self.status.value} -> {new_status.value}")
        self.status = new_status


@dataclass(frozen=True, slots=True)
class Principal:
    """Qui agit, avec quels rôles (viewer, analyst…)."""

    name: str
    roles: frozenset[str]

    def has_role(self, role: str) -> bool:
        return role in self.roles
