"""Entrée non fiable : une ligne de journal hostile est refusée, jamais interprétée."""

from pathlib import Path

import pytest

from queenbee.adapters.inbound.log_parser import MAX_LINE_LENGTH, parse_sshd_line, read_lines
from queenbee.domain.model import DomainError

GOOD = "2026-10-14T09:00:00+02:00 sshd: Failed password for admin from 10.0.0.9"


def test_parser_accepts_failed_and_accepted_lines() -> None:
    event = parse_sshd_line(GOOD)
    assert (event.source_ip, event.username, event.action) == ("10.0.0.9", "admin", "login_failed")
    assert parse_sshd_line(GOOD.replace("Failed", "Accepted")).action == "login_ok"


@pytest.mark.parametrize(
    "line",
    [
        GOOD + "; DROP TABLE incidents",  # queue parasite
        "xx " + GOOD,  # préfixe non reconnu
        GOOD.replace("admin", "ad'min"),  # caractère interdit
        GOOD.replace("10.0.0.9", "999.1.1.1"),  # IP impossible
        GOOD.replace("2026-10-14", "2026-13-45"),  # date impossible
    ],
)
def test_parser_rejects_hostile_or_malformed_lines(line: str) -> None:
    with pytest.raises(DomainError):
        parse_sshd_line(line)


def test_read_lines_skips_oversized_lines_and_keeps_going(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(f"{GOOD}\n" + "A" * (MAX_LINE_LENGTH * 3) + f"\n{GOOD}\n", encoding="utf-8")
    assert list(read_lines(log)) == [GOOD, GOOD]


def test_read_lines_respects_max_lines(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(f"{GOOD}\n" * 10, encoding="utf-8")
    assert len(list(read_lines(log, max_lines=3))) == 3
