"""Persistance : le SQL est paramétré, donc une donnée hostile reste une donnée."""

from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity

HOSTILE = "x'); DROP TABLE incidents;--"


def test_sql_injection_is_stored_as_data_not_executed() -> None:
    repo = SqliteIncidentRepository(":memory:")
    repo.add(Incident(Alert("brute_force", "10.0.0.1", Severity.HIGH, HOSTILE)))
    repo.add(Incident(Alert("port_scan", "10.0.0.2", Severity.MEDIUM, "ok")))
    stored = repo.all()
    assert [i.alert.message for i in stored] == [HOSTILE, "ok"]  # la table existe toujours
    repo.close()


def test_sqlite_roundtrip_keeps_status() -> None:
    repo = SqliteIncidentRepository(":memory:")
    incident = Incident(Alert("r", "10.0.0.1", Severity.LOW, "m"))
    incident.transition_to(IncidentStatus.TRIAGED)
    repo.add(incident)
    assert repo.all()[0].status is IncidentStatus.TRIAGED
    repo.close()


def test_in_memory_repository_returns_a_copy() -> None:
    repo = InMemoryIncidentRepository()
    repo.add(Incident(Alert("r", "10.0.0.1", Severity.LOW, "m")))
    repo.all().clear()
    assert len(repo.all()) == 1
