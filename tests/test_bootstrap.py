"""Démarrage : un seul endroit assemble les objets, et aucun état global ne survit."""

import smtplib
from pathlib import Path
from typing import Any

import pytest

from queenbee.bootstrap import build_service, main
from queenbee.config import ConfigError, SettingsBuilder
from queenbee.factories import InMemoryFactory, ProdFactory

KEY = "f" * 32


def test_no_global_state_two_services_are_independent(five_failures: list[Any]) -> None:
    settings = SettingsBuilder().with_secret_key(KEY).with_rule({"kind": "brute_force"}).build()
    first = build_service(settings, InMemoryFactory())
    second = build_service(settings, InMemoryFactory())
    assert first is not second
    assert len(first.ingest(five_failures)) == 1
    assert len(second.ingest([])) == 0


def test_prod_factory_without_smtp_cannot_build_a_notifier() -> None:
    with pytest.raises(ConfigError):
        ProdFactory(":memory:").notifier()


def test_main_runs_end_to_end_without_smtp(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    log = tmp_path / "auth.log"
    log.write_text("Failed password for root from 10.0.0.1\n" * 5, encoding="utf-8")
    env = {"QUEENBEE_SECRET_KEY": KEY, "QUEENBEE_DB_PATH": str(tmp_path / "qb.db")}
    assert main(str(log), env) == 0
    assert "1 alerte" in capsys.readouterr().out


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
        .with_secret_key(KEY)
        .with_smtp("mail.local", "qb", "pw-smtp", "qb@local", "soc@local")
        .build()
    )
    from queenbee.domain.model import Alert, Severity

    notifier = ProdFactory(":memory:", settings.smtp).notifier()
    notifier.notify(Alert("brute_force", "10.0.0.1", Severity.HIGH, "msg"))
    assert calls == ["connect mail.local", "starttls", "login qb pw-smtp", "send soc@local"]
