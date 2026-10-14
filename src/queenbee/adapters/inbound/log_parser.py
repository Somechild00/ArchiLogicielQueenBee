"""Lecture des journaux : entrée NON FIABLE. Regex ancrée, bornée, fichier fermé, taille limitée."""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path

from queenbee.domain.model import DomainError, SecurityEvent

MAX_LINE_LENGTH = 1024
MAX_LINES = 1_000_000

_FAILED_PASSWORD = re.compile(
    r"(?:[A-Za-z]{3} +\d{1,2} \d{2}:\d{2}:\d{2} \S{1,64} sshd\[\d{1,7}\]: )?"
    r"Failed password for (?:invalid user )?(?P<user>[A-Za-z0-9_.\-]{1,64}) "
    r"from (?P<ip>[0-9A-Fa-f:.]{2,45})(?: port \d{1,5})?(?: ssh2)?"
)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def parse_line(line: str, now: datetime) -> SecurityEvent | None:
    """Renvoie un événement valide ou None : une ligne hostile est ignorée, jamais exécutée."""
    if len(line) > MAX_LINE_LENGTH:
        return None
    match = _FAILED_PASSWORD.fullmatch(line.rstrip("\r\n"))
    if match is None:
        return None
    try:
        return SecurityEvent(match["ip"], match["user"], "login_failed", now)
    except DomainError:
        return None


def read_events(
    path: Path, clock: Callable[[], datetime] = _utc_now, max_lines: int = MAX_LINES
) -> Iterator[SecurityEvent]:
    """Lit un journal ligne à ligne (mémoire bornée) ; le fichier est toujours refermé."""
    now = clock()
    with path.open(encoding="utf-8", errors="replace") as handle:
        for _ in range(max_lines):
            chunk = handle.readline(MAX_LINE_LENGTH + 1)
            if not chunk:
                return
            if len(chunk) > MAX_LINE_LENGTH and not chunk.endswith("\n"):
                while chunk and not chunk.endswith("\n"):  # jette la fin de la ligne trop longue
                    chunk = handle.readline(MAX_LINE_LENGTH + 1)
                continue
            event = parse_line(chunk, now)
            if event is not None:
                yield event
