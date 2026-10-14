"""Configuration : Builder (assemblage -> validation finale -> objet figé) et secrets masqués."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from queenbee.domain.rules import Rule, build_rule

ENV_DB_PATH = "QUEENBEE_DB_PATH"
ENV_SECRET_KEY = "QUEENBEE_SECRET_KEY"  # noqa: S105  # nosec B105
ENV_SMTP_HOST = "QUEENBEE_SMTP_HOST"
ENV_SMTP_USER = "QUEENBEE_SMTP_USER"
ENV_SMTP_PASSWORD = "QUEENBEE_SMTP_PASSWORD"  # noqa: S105  # nosec B105
ENV_ALERT_SENDER = "QUEENBEE_ALERT_SENDER"
ENV_ALERT_RECIPIENT = "QUEENBEE_ALERT_RECIPIENT"

# Les deux constantes ENV_*SECRET/PASSWORD sont des NOMS de variables, pas des secrets.
MIN_SECRET_LENGTH = 32
_HOST_RE = re.compile(r"[A-Za-z0-9.\-]{1,253}")


class ConfigError(ValueError):
    """Configuration invalide ou incomplète (les messages ne contiennent jamais de secret)."""


class Secret:
    """Valeur sensible : ne s'affiche jamais (repr, str, f-string, logs)."""

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        """Seul point d'accès à la valeur : à appeler au dernier moment, jamais pour logger."""
        return self._value

    def __repr__(self) -> str:
        return "Secret(***)"

    __str__ = __repr__

    def __len__(self) -> int:
        return len(self._value)


@dataclass(frozen=True, slots=True)
class SmtpSettings:
    host: str
    username: str
    password: Secret = field(repr=False)
    sender: str
    recipient: str


@dataclass(frozen=True, slots=True)
class Settings:
    db_path: str
    secret_key: Secret = field(repr=False)
    rules: tuple[Rule, ...]
    smtp: SmtpSettings | None = None


class SettingsBuilder:
    """Assemble pas à pas ; rien n'est validé avant build(), qui renvoie un objet figé."""

    def __init__(self) -> None:
        self._db_path = "queenbee.db"
        self._secret_key: str | None = None
        self._rule_specs: list[Mapping[str, object]] = []
        self._smtp: dict[str, str] | None = None

    def with_db_path(self, path: str) -> SettingsBuilder:
        self._db_path = path
        return self

    def with_secret_key(self, key: str) -> SettingsBuilder:
        self._secret_key = key
        return self

    def with_rule(self, spec: Mapping[str, object]) -> SettingsBuilder:
        self._rule_specs.append(spec)
        return self

    def with_smtp(
        self, host: str, username: str, password: str, sender: str, recipient: str
    ) -> SettingsBuilder:
        self._smtp = {
            "host": host,
            "username": username,
            "password": password,
            "sender": sender,
            "recipient": recipient,
        }
        return self

    def build(self) -> Settings:
        if not self._db_path:
            raise ConfigError("chemin de base de données vide")
        if self._secret_key is None or len(self._secret_key) < MIN_SECRET_LENGTH:
            raise ConfigError(f"clé secrète absente ou trop courte (minimum {MIN_SECRET_LENGTH})")
        rules = tuple(build_rule(spec) for spec in self._rule_specs)  # DomainError si non conforme
        return Settings(
            db_path=self._db_path,
            secret_key=Secret(self._secret_key),
            rules=rules,
            smtp=self._build_smtp(),
        )

    def _build_smtp(self) -> SmtpSettings | None:
        if self._smtp is None:
            return None
        if _HOST_RE.fullmatch(self._smtp["host"]) is None:
            raise ConfigError("hôte SMTP invalide")
        if not self._smtp["password"]:
            raise ConfigError("mot de passe SMTP vide")
        return SmtpSettings(
            host=self._smtp["host"],
            username=self._smtp["username"],
            password=Secret(self._smtp["password"]),
            sender=self._smtp["sender"],
            recipient=self._smtp["recipient"],
        )


def read_env_file(path: Path) -> dict[str, str]:
    """Lit un fichier .env minimal (CLE=valeur, # commentaires). Absent -> dictionnaire vide."""
    if not path.is_file():
        return {}
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip("'\"")
    return values


def settings_from_env(env: Mapping[str, str]) -> Settings:
    """Construit les réglages depuis l'environnement ; les secrets ne sont jamais dans le code."""
    builder = SettingsBuilder()
    if ENV_DB_PATH in env:
        builder.with_db_path(env[ENV_DB_PATH])
    builder.with_secret_key(env.get(ENV_SECRET_KEY, ""))
    builder.with_rule({"kind": "brute_force"}).with_rule({"kind": "port_scan"})
    if ENV_SMTP_HOST in env:
        builder.with_smtp(
            host=env[ENV_SMTP_HOST],
            username=env.get(ENV_SMTP_USER, ""),
            password=env.get(ENV_SMTP_PASSWORD, ""),
            sender=env.get(ENV_ALERT_SENDER, ""),
            recipient=env.get(ENV_ALERT_RECIPIENT, ""),
        )
    return builder.build()
