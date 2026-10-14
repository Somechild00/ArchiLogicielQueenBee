"""Adaptateurs de persistance."""

from __future__ import annotations

import sqlite3

from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity

_CREATE = (
    "CREATE TABLE IF NOT EXISTS incidents ("
    "id INTEGER PRIMARY KEY AUTOINCREMENT, rule TEXT NOT NULL, source_ip TEXT NOT NULL, "
    "severity TEXT NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL)"
)
_SELECT = "SELECT rule, source_ip, severity, message, status FROM incidents ORDER BY id"


class InMemoryIncidentRepository:
    def __init__(self) -> None:
        self._items: list[Incident] = []

    def add(self, incident: Incident) -> None:
        self._items.append(incident)

    def all(self) -> list[Incident]:
        return list(self._items)


class SqliteIncidentRepository:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute(_CREATE)
        self._conn.commit()

    def add(self, incident: Incident) -> None:
        alert = incident.alert
        # TODO fix: requête construite par f-string, reprise telle quelle du script hérité
        self._conn.execute(
            "INSERT INTO incidents (rule, source_ip, severity, message, status) VALUES ("
            f"'{alert.rule}', '{alert.source_ip}', '{alert.severity.value}', "
            f"'{alert.message}', '{incident.status.value}')"
        )
        self._conn.commit()

    def all(self) -> list[Incident]:
        rows = self._conn.execute(_SELECT).fetchall()
        return [
            Incident.restore(Alert(rule, ip, Severity(sev), msg), IncidentStatus(status))
            for rule, ip, sev, msg, status in rows
        ]

    def close(self) -> None:
        self._conn.close()
