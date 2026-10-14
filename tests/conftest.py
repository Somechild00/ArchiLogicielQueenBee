"""Fixtures partagées (reconstitué : garde ta version si elle existe déjà)."""

from datetime import UTC, datetime

import pytest

from queenbee.domain.model import SecurityEvent

T0 = datetime(2026, 10, 14, 14, 0, tzinfo=UTC)


def ev(
    ip: str = "10.0.0.1",
    user: str = "root",
    action: str = "login_failed",
    ts: datetime = T0,
) -> SecurityEvent:
    return SecurityEvent(ip, user, action, ts)


@pytest.fixture
def five_failures() -> list[SecurityEvent]:
    return [ev() for _ in range(5)]
