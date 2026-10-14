"""Adaptateurs de notification."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

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
        message = EmailMessage()  # EmailMessage refuse les retours à la ligne dans les en-têtes
        message["From"] = self._sender
        message["To"] = self._recipient
        message["Subject"] = f"[Queen Bee] {alert.rule} ({alert.severity.value})"
        message.set_content(alert.message)
        with smtplib.SMTP(self._host) as smtp:
            smtp.starttls()
            smtp.login(self._username, self._password)
            smtp.send_message(message)
