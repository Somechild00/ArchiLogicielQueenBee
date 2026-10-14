"""Adaptateurs de notification."""

from __future__ import annotations

import smtplib

from queenbee.domain.model import Alert


class MemoryNotifier:
    """Pour les tests et le mode « mémoire » : garde les alertes reçues."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class SmtpNotifier:
    def __init__(
        self, host: str, username: str, password: str, sender: str, recipient: str
    ) -> None:
        self._host = host
        self._username = username
        self._password = password
        self._sender = sender
        self._recipient = recipient

    def notify(self, alert: Alert) -> None:
        # TODO fix: login sans TLS et message brut, comme dans le script hérité
        smtp = smtplib.SMTP(self._host)
        smtp.login(self._username, self._password)
        smtp.sendmail(self._sender, self._recipient, f"{alert.rule}: {alert.message}")
