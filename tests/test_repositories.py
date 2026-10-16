"""Persistance : le SQL est paramétré, donc une donnée hostile reste une donnée."""

import sqlite3

from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity

HOSTILE = "x'); DROP TABLE incidents;--"


def test_sql_injection_is_stored_as_data_not_executed() -> None:
    repo = SqliteIncidentRepository(sqlite3.connect(":memory:"))
    repo.save(Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, HOSTILE)))
    repo.save(Incident(Alert("port_scan", "10.0.0.2", Severity.MEDIUM, "ok")))
    stored = repo.list_open()
    assert [i.alert.message for i in stored] == [HOSTILE, "ok"]  # la table existe toujours


def test_sqlite_roundtrip_keeps_status_and_updates_in_place() -> None:
    repo = SqliteIncidentRepository(sqlite3.connect(":memory:"))
    incident = Incident(Alert("r", "10.0.0.1", Severity.LOW, "m"))
    repo.save(incident)
    incident.transition_to(IncidentStatus.TRIAGED)
    repo.save(incident)  # mise à jour, pas de doublon
    stored = repo.get(incident.id)
    assert stored is not None
    assert stored.status is IncidentStatus.TRIAGED
    assert len(repo.list_open()) == 1


def test_closed_incidents_are_not_listed_as_open() -> None:
    repo = InMemoryIncidentRepository()
    incident = Incident(Alert("r", "10.0.0.1", Severity.LOW, "m"))
    incident.transition_to(IncidentStatus.TRIAGED)
    incident.transition_to(IncidentStatus.CLOSED)
    repo.save(incident)
    assert repo.list_open() == []
    assert repo.get(incident.id) is incident
