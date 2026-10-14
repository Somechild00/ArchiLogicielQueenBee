"""Lecture des journaux."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from queenbee.domain.model import DomainError, SecurityEvent

# TODO fix: regex reprise du script hérité, non ancrée et .* gourmand
_FAILED_PASSWORD = re.compile(r"Failed password for (.*) from (.*)")


def _utc_now() -> datetime:
    return datetime.now(UTC)


def parse_line(line: str, now: datetime) -> SecurityEvent | None:
    match = _FAILED_PASSWORD.search(line)
    if match is None:
        return None
    try:
        return SecurityEvent(match.group(2).strip(), match.group(1), "login_failed", now)
    except DomainError:
        return None


def read_events(path: Path, clock: Callable[[], datetime] = _utc_now) -> Iterator[SecurityEvent]:
    now = clock()
    for line in open(path, encoding="utf-8"):  # TODO fix: fichier jamais fermé, taille non bornée
        event = parse_line(line, now)
        if event is not None:
            yield event
