"""Adaptateur : ligne de journal sshd -> SecurityEvent. Entrée NON FIABLE.

Borne la taille AVANT la regex, regex ancrée (fullmatch) sans quantificateur imbriqué,
classes bornées au lieu de .*, puis le domaine revalide. Fichier toujours refermé.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

from queenbee.domain.model import DomainError, SecurityEvent

MAX_LINE_LENGTH = 512
MAX_LINES = 1_000_000

_SSHD = re.compile(
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})"
    r" sshd: (?P<result>Failed|Accepted) password for "
    r"(?P<user>[A-Za-z0-9_.\-]{1,64}) from (?P<ip>[0-9a-fA-F:.]{2,45})"
)


def parse_sshd_line(line: str) -> SecurityEvent:
    """Renvoie un événement valide, ou lève DomainError. Jamais d'autre exception."""
    if not isinstance(line, str) or len(line) > MAX_LINE_LENGTH:
        raise DomainError("ligne trop longue")
    match = _SSHD.fullmatch(line.strip())
    if match is None:
        raise DomainError("format non reconnu")
    try:
        timestamp = datetime.fromisoformat(match["ts"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    action = "login_failed" if match["result"] == "Failed" else "login_ok"
    return SecurityEvent(match["ip"], match["user"], action, timestamp)  # le domaine revalide


def read_lines(path: Path, max_lines: int = MAX_LINES) -> Iterator[str]:
    """Lit un journal ligne à ligne (mémoire bornée) ; les lignes géantes sont jetées."""
    with path.open(encoding="utf-8", errors="replace") as handle:
        for _ in range(max_lines):
            chunk = handle.readline(MAX_LINE_LENGTH + 1)
            if not chunk:
                return
            if len(chunk) > MAX_LINE_LENGTH and not chunk.endswith("\n"):
                while chunk and not chunk.endswith("\n"):  # jette la fin de la ligne trop longue
                    chunk = handle.readline(MAX_LINE_LENGTH + 1)
                continue
            yield chunk.rstrip("\r\n")
