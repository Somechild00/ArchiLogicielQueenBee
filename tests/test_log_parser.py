"""Entrée non fiable : une ligne de journal hostile est ignorée, jamais interprétée."""

from pathlib import Path

import pytest

from queenbee.adapters.inbound.log_parser import MAX_LINE_LENGTH, parse_line, read_events
from tests.conftest import T0

SSHD = (
    "Oct 14 14:00:01 srv sshd[812]: "
    "Failed password for invalid user admin from 10.0.0.9 port 22 ssh2"
)


def test_parser_accepts_a_real_sshd_line() -> None:
    event = parse_line(SSHD, T0)
    assert event is not None
    assert (event.source_ip, event.user, event.action) == ("10.0.0.9", "admin", "login_failed")


@pytest.mark.parametrize(
    "line",
    [
        "Failed password for root from 10.0.0.1; DROP TABLE incidents",  # queue parasite
        "xx Failed password for root from 10.0.0.1",  # préfixe non reconnu (non ancré avant)
        "Failed password for ro'ot from 10.0.0.1",  # caractère interdit
        "Failed password for root from 999.1.1.1",  # IP impossible
        "Failed password for " + "a" * 5000 + " from 10.0.0.1",  # ligne gigantesque
        "",
    ],
)
def test_parser_ignores_hostile_or_malformed_lines(line: str) -> None:
    assert parse_line(line, T0) is None


def test_read_events_skips_oversized_lines_and_keeps_going(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "Failed password for root from 10.0.0.1\n"
        + "A" * (MAX_LINE_LENGTH * 3)
        + "\nFailed password for bob from 10.0.0.2\n",
        encoding="utf-8",
    )
    events = list(read_events(log, clock=lambda: T0))
    assert [e.user for e in events] == ["root", "bob"]


def test_read_events_respects_max_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root from 10.0.0.1\n" * 10, encoding="utf-8")
    assert len(list(read_events(log, clock=lambda: T0, max_lines=3))) == 3


def test_read_events_default_clock_gives_aware_timestamps(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root from 10.0.0.1\n", encoding="utf-8")
    assert next(read_events(log)).timestamp.tzinfo is not None
