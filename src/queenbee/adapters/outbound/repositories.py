"""Adaptateurs de sortie : dépôt mémoire (tests) et sqlite (prod). SQL toujours paramétré."""

from __future__ import annotations

import sqlite3
from uuid import UUID

from queenbee.domain.model import Alert, Incident, IncidentStatus, Severity


class InMemoryIncidentRepository:
    def __init__(self) -> None:
        self._items: dict[UUID, Incident] = {}

    def save(self, incident: Incident) -> None:
        self._items[incident.id] = incident

    def get(self, incident_id: UUID) -> Incident | None:
        return self._items.get(incident_id)

    def list_open(self) -> list[Incident]:
        return [i for i in self._items.values() if i.status is not IncidentStatus.CLOSED]


class SqliteIncidentRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        conn.execute(
            "CREATE TABLE IF NOT EXISTS incidents ("
            "id TEXT PRIMARY KEY, rule TEXT NOT NULL, source_ip TEXT NOT NULL, "
            "severity INTEGER NOT NULL, message TEXT NOT NULL, status TEXT NOT NULL)"
        )

    def save(self, incident: Incident) -> None:
        a = incident.alert
        self._conn.execute(
            "INSERT INTO incidents (id, rule, source_ip, severity, message, status) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET status = excluded.status",
            (
                str(incident.id),
                a.rule,
                a.source_ip,
                int(a.severity),
                a.message,
                incident.status.value,
            ),
        )
        self._conn.commit()

    def get(self, incident_id: UUID) -> Incident | None:
        row = self._conn.execute(
            "SELECT id, rule, source_ip, severity, message, status FROM incidents WHERE id = ?",
            (str(incident_id),),
        ).fetchone()
        return self._to_incident(row) if row else None

    def list_open(self) -> list[Incident]:
        rows = self._conn.execute(
            "SELECT id, rule, source_ip, severity, message, status FROM incidents "
            "WHERE status != ? ORDER BY rowid",
            (IncidentStatus.CLOSED.value,),
        ).fetchall()
        return [self._to_incident(r) for r in rows]

    @staticmethod
    def _to_incident(row: tuple[str, str, str, int, str, str]) -> Incident:
        id_, rule, ip, severity, message, status = row
        return Incident(
            Alert(rule, ip, Severity(severity), message),
            id=UUID(id_),
            status=IncidentStatus(status),
        )
