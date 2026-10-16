"""Configuration : Builder (assemblage -> validation finale -> objet figé) et secrets masqués."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path

from queenbee.domain.rules import Rule, build_rule

# Ce sont des NOMS de variables d'environnement, pas des secrets.
ENV_AGENT_KEY = "QUEENBEE_AGENT_KEY"
ENV_DB_PATH = "QUEENBEE_DB"
ENV_BF_THRESHOLD = "QUEENBEE_BF_THRESHOLD"
ENV_SMTP_HOST = "QUEENBEE_SMTP_HOST"
ENV_SMTP_USER = "QUEENBEE_SMTP_USER"
ENV_SMTP_PASSWORD = "QUEENBEE_SMTP_PASSWORD"  # noqa: S105  # nosec B105
ENV_ALERT_SENDER = "QUEENBEE_ALERT_SENDER"
ENV_ALERT_RECIPIENT = "QUEENBEE_ALERT_RECIPIENT"

MIN_KEY_BYTES = 32
_HOST_RE = re.compile(r"[A-Za-z0-9.\-]{1,253}")


class ConfigError(ValueError):
    """Configuration invalide ou incomplète (les messages ne contiennent jamais de secret)."""


class Secret[T: (str, bytes)]:
    """Valeur sensible : ne s'affiche jamais (repr, str, f-string, journaux)."""

    __slots__ = ("_value",)
    _value: T

    def __init__(self, value: T) -> None:
        self._value = value

    def reveal(self) -> T:
        """Seul point d'accès à la valeur : à appeler au dernier moment, jamais pour journaliser."""
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
    password: Secret[str] = field(repr=False)
    sender: str
    recipient: str


@dataclass(frozen=True, slots=True)
class Settings:
    agent_key: Secret[bytes] = field(repr=False)
    db_path: str = ":memory:"
    rules: tuple[Rule, ...] = ()
    smtp: SmtpSettings | None = None


class SettingsBuilder:
    """Assemble pas à pas ; rien n'est validé avant build(), qui renvoie un objet figé."""

    def __init__(self) -> None:
        self._key: bytes | None = None
        self._db_path = ":memory:"
        self._rule_specs: list[Mapping[str, object]] = []
        self._smtp: dict[str, str] | None = None

    def hmac_key(self, key: bytes) -> SettingsBuilder:
        self._key = key
        return self

    def db_path(self, path: str) -> SettingsBuilder:
        self._db_path = path
        return self

    def rule(self, spec: Mapping[str, object]) -> SettingsBuilder:
        self._rule_specs.append(spec)
        return self

    def smtp(
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
        if not isinstance(self._key, bytes) or len(self._key) < MIN_KEY_BYTES:
            raise ConfigError(f"clé HMAC absente ou < {MIN_KEY_BYTES} octets")
        if not self._db_path:
            raise ConfigError("chemin de base de données vide")
        specs = self._rule_specs or [{"kind": "brute_force"}, {"kind": "port_scan"}]
        rules = tuple(build_rule(spec) for spec in specs)  # DomainError si non conforme
        return Settings(
            agent_key=Secret(self._key),
            db_path=self._db_path,
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
    """Lit la clé au démarrage : pas de valeur par défaut, sans clé pas de démarrage."""
    raw_key = env.get(ENV_AGENT_KEY)
    if raw_key is None:
        raise ConfigError(f"{ENV_AGENT_KEY} non défini")
    try:
        key = bytes.fromhex(raw_key)
    except ValueError as exc:
        raise ConfigError(f"{ENV_AGENT_KEY} doit être en hexadécimal") from exc
    builder = SettingsBuilder().hmac_key(key)
    if ENV_DB_PATH in env:
        builder.db_path(env[ENV_DB_PATH])
    threshold: object = 5
    if ENV_BF_THRESHOLD in env:
        try:
            threshold = int(env[ENV_BF_THRESHOLD])
        except ValueError as exc:
            raise ConfigError(f"{ENV_BF_THRESHOLD} doit être un entier") from exc
    builder.rule({"kind": "brute_force", "threshold": threshold}).rule({"kind": "port_scan"})
    if ENV_SMTP_HOST in env:
        builder.smtp(
            host=env[ENV_SMTP_HOST],
            username=env.get(ENV_SMTP_USER, ""),
            password=env.get(ENV_SMTP_PASSWORD, ""),
            sender=env.get(ENV_ALERT_SENDER, ""),
            recipient=env.get(ENV_ALERT_RECIPIENT, ""),
        )
    return builder.build()
