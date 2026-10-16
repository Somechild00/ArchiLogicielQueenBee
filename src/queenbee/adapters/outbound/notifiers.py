"""Adaptateurs de notification : même interface Notifier pour tous (Décorateur, Observateur).

Le mot de passe SMTP vient des réglages, jamais du code.
"""

from __future__ import annotations

import logging
import smtplib
import time
from collections.abc import Callable, Sequence
from email.message import EmailMessage

from queenbee.application.ports import Notifier
from queenbee.config import SmtpSettings
from queenbee.domain.model import Alert, Severity

_audit = logging.getLogger("queenbee.audit")
_log = logging.getLogger(__name__)


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
        message["Subject"] = f"[Queen Bee] {alert.rule} ({Severity(alert.severity).name})"
        message.set_content(alert.message)
        with smtplib.SMTP(self._settings.host) as smtp:
            smtp.starttls()
            smtp.login(self._settings.username, self._settings.password.reveal())
            smtp.send_message(message)


class RateLimitedNotifier:
    """Décorateur anti-inondation : au plus max_per_window alertes par fenêtre, le reste compté."""

    def __init__(
        self,
        inner: Notifier,
        max_per_window: int,
        window_s: float,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._inner, self._max, self._window, self._clock = inner, max_per_window, window_s, clock
        self._window_start = clock()
        self._sent = 0
        self.dropped = 0

    def notify(self, alert: Alert) -> None:
        now = self._clock()
        if now - self._window_start >= self._window:
            self._window_start, self._sent = now, 0
        if self._sent >= self._max:
            self.dropped += 1  # compté, jamais silencieux
            return
        self._sent += 1
        self._inner.notify(alert)


class AuditedNotifier:
    """Décorateur d'audit : chaque alerte laisse une trace (preuve, non-répudiation)."""

    def __init__(self, inner: Notifier) -> None:
        self._inner = inner

    def notify(self, alert: Alert) -> None:
        _audit.info("alert rule=%s ip=%s severity=%s", alert.rule, alert.source_ip, alert.severity)
        self._inner.notify(alert)


class FanOutNotifier:
    """Observateur : un abonné en panne ne bloque pas les autres, la panne est comptée."""

    def __init__(self, subscribers: Sequence[Notifier]) -> None:
        self._subscribers = tuple(subscribers)
        self.failures = 0

    def notify(self, alert: Alert) -> None:
        for subscriber in self._subscribers:
            try:
                subscriber.notify(alert)
            except Exception:  # un abonné défaillant ne doit pas faire tomber la diffusion
                self.failures += 1
                _log.exception("subscriber failed")
