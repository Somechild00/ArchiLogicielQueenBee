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

KEY = "a1b2c3d4" * 8
SMTP_PASSWORD = "mot-de-passe-smtp-très-secret"  # noqa: S105


def full_settings() -> str:
    settings = (
        SettingsBuilder()
        .with_secret_key(KEY)
        .with_rule({"kind": "brute_force", "threshold": 3})
        .with_smtp("mail.local", "queenbee", SMTP_PASSWORD, "qb@local", "soc@local")
        .build()
    )
    return f"{settings!r} {settings} {settings.smtp!r}"


def test_secret_never_appears_in_repr_or_str() -> None:
    shown = full_settings()
    assert KEY not in shown
    assert SMTP_PASSWORD not in shown


def test_secret_wrapper_hides_value_everywhere() -> None:
    secret = Secret(KEY)
    assert KEY not in f"{secret} {secret!r} {[secret]} {{'k': secret}}"
    assert secret.reveal() == KEY


def test_secret_is_read_from_environment_not_from_code() -> None:
    env = {"QUEENBEE_SECRET_KEY": KEY, "QUEENBEE_DB_PATH": "x.db"}
    settings = settings_from_env(env)
    assert settings.secret_key.reveal() == KEY
    assert settings.db_path == "x.db"
    assert settings.smtp is None


def test_secret_missing_from_environment_is_an_error() -> None:
    with pytest.raises(ConfigError):
        settings_from_env({})


def test_settings_are_frozen_after_build() -> None:
    settings = SettingsBuilder().with_secret_key(KEY).build()
    with pytest.raises(FrozenInstanceError):
        settings.db_path = "ailleurs.db"  # type: ignore[misc]


def test_builder_validates_only_at_build_time() -> None:
    builder = SettingsBuilder().with_rule({"kind": "inconnue"})  # pas encore d'erreur
    assert builder is not None


@pytest.mark.parametrize("host", ["", "mail local", "mail;rm -rf"])
def test_builder_rejects_invalid_smtp_host(host: str) -> None:
    builder = SettingsBuilder().with_secret_key(KEY).with_smtp(host, "u", "p", "a@b", "c@d")
    with pytest.raises(ConfigError):
        builder.build()


def test_builder_rejects_empty_smtp_secret() -> None:
    builder = SettingsBuilder().with_secret_key(KEY).with_smtp("mail.local", "u", "", "a@b", "c@d")
    with pytest.raises(ConfigError):
        builder.build()


def test_builder_rejects_empty_db_path() -> None:
    with pytest.raises(ConfigError):
        SettingsBuilder().with_secret_key(KEY).with_db_path("").build()


def test_settings_from_env_with_smtp() -> None:
    env = {
        "QUEENBEE_SECRET_KEY": KEY,
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
    env_file.write_text("# commentaire\n\nQUEENBEE_SECRET_KEY='abc'\nsans_egal\nA = b\n")
    assert read_env_file(env_file) == {"QUEENBEE_SECRET_KEY": "abc", "A": "b"}
    assert read_env_file(tmp_path / "absent.env") == {}
