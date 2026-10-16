"""Configuration : le secret ne s'affiche jamais ; le Builder valide à la fin et fige."""

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from queenbee.config import (
    ConfigError,
    Secret,
    SettingsBuilder,
    read_env_file,
    settings_from_env,
)
from queenbee.domain.model import DomainError

KEY = bytes(range(32))
SMTP_PASSWORD = "mot-de-passe-smtp-très-secret"  # noqa: S105


def test_secret_never_appears_in_repr_or_str() -> None:
    settings = (
        SettingsBuilder()
        .hmac_key(KEY)
        .rule({"kind": "brute_force", "threshold": 3})
        .smtp("mail.local", "queenbee", SMTP_PASSWORD, "qb@local", "soc@local")
        .build()
    )
    shown = f"{settings!r} {settings} {settings.smtp!r}"
    assert KEY.hex() not in shown
    assert repr(KEY) not in shown
    assert SMTP_PASSWORD not in shown


def test_secret_wrapper_hides_value_everywhere() -> None:
    secret = Secret("valeur-sensible")
    assert "valeur-sensible" not in f"{secret} {secret!r} {[secret]} {{'k': secret}}"
    assert secret.reveal() == "valeur-sensible"
    assert len(secret) == len("valeur-sensible")


def test_key_is_read_from_environment_not_from_code() -> None:
    settings = settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_DB": "x.db"})
    assert settings.agent_key.reveal() == KEY
    assert settings.db_path == "x.db"
    assert settings.smtp is None


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"QUEENBEE_AGENT_KEY": "pas-de-l-hexa"},
        {"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "cinq"},
    ],
)
def test_bad_environment_refuses_to_start(env: dict[str, str]) -> None:
    with pytest.raises(ConfigError):
        settings_from_env(env)


def test_threshold_from_environment_is_validated() -> None:
    settings = settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "3"})
    assert len(settings.rules) == 2
    with pytest.raises(DomainError):
        settings_from_env({"QUEENBEE_AGENT_KEY": KEY.hex(), "QUEENBEE_BF_THRESHOLD": "0"})


def test_settings_are_frozen_after_build() -> None:
    settings = SettingsBuilder().hmac_key(KEY).build()
    with pytest.raises(FrozenInstanceError):
        settings.db_path = "ailleurs.db"  # type: ignore[misc]


def test_builder_validates_only_at_build_time() -> None:
    builder = SettingsBuilder().rule({"kind": "inconnue"})  # pas encore d'erreur
    with pytest.raises(ConfigError):
        builder.build()  # la clé manque : refus avant même de regarder la règle


@pytest.mark.parametrize("host", ["", "mail local", "mail;rm -rf"])
def test_builder_rejects_invalid_smtp_host(host: str) -> None:
    builder = SettingsBuilder().hmac_key(KEY).smtp(host, "u", "p", "a@b", "c@d")
    with pytest.raises(ConfigError):
        builder.build()


def test_builder_rejects_empty_smtp_secret_and_empty_db_path() -> None:
    with pytest.raises(ConfigError):
        SettingsBuilder().hmac_key(KEY).smtp("mail.local", "u", "", "a@b", "c@d").build()
    with pytest.raises(ConfigError):
        SettingsBuilder().hmac_key(KEY).db_path("").build()


def test_settings_from_env_with_smtp() -> None:
    env = {
        "QUEENBEE_AGENT_KEY": KEY.hex(),
        "QUEENBEE_SMTP_HOST": "mail.local",
        "QUEENBEE_SMTP_USER": "queenbee",
        "QUEENBEE_SMTP_PASSWORD": SMTP_PASSWORD,
        "QUEENBEE_ALERT_SENDER": "qb@local",
        "QUEENBEE_ALERT_RECIPIENT": "soc@local",
    }
    settings = settings_from_env(env)
    assert settings.smtp is not None
    assert settings.smtp.password.reveal() == SMTP_PASSWORD
    assert SMTP_PASSWORD not in repr(settings)


def test_read_env_file_parses_keys_and_ignores_comments(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("# commentaire\n\nQUEENBEE_AGENT_KEY='abc'\nsans_egal\nA = b\n")
    assert read_env_file(env_file) == {"QUEENBEE_AGENT_KEY": "abc", "A": "b"}
    assert read_env_file(tmp_path / "absent.env") == {}
