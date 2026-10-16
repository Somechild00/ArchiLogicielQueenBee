"""A1 (Observateur, bonus) + A3 : cas d'usage, lecteur qui modifie, parité des adaptateurs."""

import sqlite3
from collections.abc import Callable
from uuid import uuid4

import pytest

from queenbee.adapters.outbound.notifiers import FanOutNotifier
from queenbee.adapters.outbound.repositories import (
    InMemoryIncidentRepository,
    SqliteIncidentRepository,
)
from queenbee.application.access import IncidentReadProxy
from queenbee.application.ports import IncidentRepository
from queenbee.application.services import AccessDeniedError, DetectionService, IncidentService
from queenbee.domain.model import Alert, DomainError, IncidentStatus, Principal, SecurityEvent
from queenbee.domain.rules import BruteForceRule

ANALYST = Principal("alice", frozenset({"analyst"}))
VIEWER = Principal("bob", frozenset({"viewer"}))
Factory = Callable[[], IncidentRepository]


@pytest.fixture(params=["memory", "sqlite"])
def make_repo(request: pytest.FixtureRequest) -> Factory:
    if request.param == "memory":
        return InMemoryIncidentRepository
    return lambda: SqliteIncidentRepository(sqlite3.connect(":memory:"))


class Spy:
    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class Broken:
    def notify(self, alert: Alert) -> None:
        raise RuntimeError("smtp down")


def test_observer_failure_does_not_block_other_subscribers(
    five_failures: list[SecurityEvent],
) -> None:
    spy = Spy()
    fan = FanOutNotifier([Broken(), spy])
    DetectionService(BruteForceRule(), InMemoryIncidentRepository(), [fan]).ingest(five_failures)
    assert len(spy.received) == 1
    assert fan.failures == 1


def test_reader_cannot_modify_through_proxy(
    make_repo: Factory, five_failures: list[SecurityEvent]
) -> None:
    repo = make_repo()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    proxy = IncidentReadProxy(repo, VIEWER)
    assert proxy.list_open() == [inc]
    assert not hasattr(proxy, "save")  # aucune écriture exposée
    with pytest.raises(AccessDeniedError):
        IncidentService(repo).move(VIEWER, inc.id, IncidentStatus.TRIAGED)
    stored = repo.get(inc.id)
    assert stored is not None
    assert stored.status is IncidentStatus.OPEN  # aucun effet de bord


def test_denied_reads_are_counted() -> None:
    proxy = IncidentReadProxy(InMemoryIncidentRepository(), Principal("g", frozenset()))
    for _ in range(3):
        with pytest.raises(AccessDeniedError):
            proxy.list_open()
    assert proxy.denied == 3


def test_business_rule_runs_before_persistence(
    make_repo: Factory, five_failures: list[SecurityEvent]
) -> None:
    repo = make_repo()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    with pytest.raises(DomainError):
        IncidentService(repo).move(ANALYST, inc.id, IncidentStatus.CLOSED)  # saute le triage
    stored = repo.get(inc.id)
    assert stored is not None
    assert stored.status is IncidentStatus.OPEN


def test_full_lifecycle_same_behaviour_on_both_adapters(
    make_repo: Factory, five_failures: list[SecurityEvent]
) -> None:
    repo = make_repo()
    [inc] = DetectionService(BruteForceRule(), repo, []).ingest(five_failures)
    service = IncidentService(repo)
    service.move(ANALYST, inc.id, IncidentStatus.TRIAGED)
    service.move(ANALYST, inc.id, IncidentStatus.CLOSED)
    assert repo.list_open() == []
    with pytest.raises(DomainError):
        service.move(ANALYST, uuid4(), IncidentStatus.TRIAGED)
