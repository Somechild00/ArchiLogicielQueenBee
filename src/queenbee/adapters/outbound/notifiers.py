"""Adaptateurs de notification. Le mot de passe SMTP vient des réglages, jamais du code."""

from __future__ import annotations

import smtplib
from email.message import EmailMessage

from queenbee.config import SmtpSettings
from queenbee.domain.model import Alert


class MemoryNotifier:
    """Pour les tests et le mode « mémoire » : garde les alertes reçues."""

    def __init__(self) -> None:
        self.received: list[Alert] = []

    def notify(self, alert: Alert) -> None:
        self.received.append(alert)


class SmtpNotifier:
    def __init__(self, settings: SmtpSettings) -> None:
        self._settings = settings

    def notify(self, alert: Alert) -> None:
        message = EmailMessage()  # EmailMessage refuse les retours à la ligne dans les en-têtes
        message["From"] = self._settings.sender
        message["To"] = self._settings.recipient
        message["Subject"] = f"[Queen Bee] {alert.rule} ({alert.severity.value})"
        message.set_content(alert.message)
        with smtplib.SMTP(self._settings.host) as smtp:
            smtp.starttls()
            smtp.login(self._settings.username, self._settings.password.reveal())
            smtp.send_message(message)
