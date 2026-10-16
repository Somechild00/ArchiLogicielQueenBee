"""Démarrage : un seul endroit assemble les objets, et aucun état global ne survit."""

import smtplib
from pathlib import Path
from typing import Any

import pytest

from queenbee.bootstrap import build_app, main
from queenbee.config import ConfigError, SettingsBuilder
from queenbee.domain.model import Alert, IncidentStatus, Principal, Severity
from queenbee.factories import InMemoryFactory, ProdFactory

KEY = bytes(range(32))
LINE = "2026-10-14T09:00:00+02:00 sshd: Failed password for root from 10.0.0.66"


def test_no_global_state_two_apps_are_independent() -> None:
    settings = SettingsBuilder().hmac_key(KEY).build()
    first = build_app(settings, InMemoryFactory())
    second = build_app(settings, InMemoryFactory())
    assert first is not second
    assert len(first.ingest_lines([LINE] * 5)) == 1
    assert second.ingest_lines([]) == []


def test_full_story_detect_triage_contain_close() -> None:
    app = build_app(SettingsBuilder().hmac_key(KEY).build(), InMemoryFactory())
    [incident] = app.ingest_lines([LINE] * 5)
    alice = Principal("alice", frozenset({"analyst"}))
    for status in (IncidentStatus.TRIAGED, IncidentStatus.CONTAINED, IncidentStatus.CLOSED):
        app.incidents.move(alice, incident.id, status)
    assert incident.status is IncidentStatus.CLOSED


def test_prod_factory_without_smtp_cannot_build_a_notifier() -> None:
    with pytest.raises(ConfigError):
        ProdFactory(":memory:").notifier()


def test_main_runs_end_to_end_without_smtp(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    log = tmp_path / "auth.log"
    log.write_text(f"{LINE}\n" * 5 + "garbage\n", encoding="utf-8")
    env = {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_DB": str(tmp_path / "qb.db")}
    assert main(str(log), env) == 0
    assert "1 incident(s) ouvert(s), 1 ligne(s) rejetée(s)" in capsys.readouterr().out


def test_smtp_notifier_uses_tls_and_reveals_secret_only_to_login(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class FakeSMTP:
        def __init__(self, host: str) -> None:
            calls.append(f"connect {host}")

        def __enter__(self) -> "FakeSMTP":
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def starttls(self) -> None:
            calls.append("starttls")

        def login(self, user: str, password: str) -> None:
            calls.append(f"login {user} {password}")

        def send_message(self, message: Any) -> None:
            calls.append(f"send {message['To']}")

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    settings = (
        SettingsBuilder()
        .hmac_key(KEY)
        .smtp("mail.local", "qb", "pw-smtp", "qb@local", "soc@local")
        .build()
    )
    app = build_app(settings)  # famille production : SMTP audité et limité
    assert app.ingest_lines([]) == []
    ProdFactory(":memory:", settings.smtp).notifier().notify(
        Alert("brute_force", "10.0.0.1", Severity.HIGH, "msg")
    )
    assert calls == ["connect mail.local", "starttls", "login qb pw-smtp", "send soc@local"]
