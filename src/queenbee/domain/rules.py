"""Règles de détection : Strategy (chaque règle), Composite (RuleSet), Factory (build_rule)."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Protocol

from queenbee.domain.model import Alert, DomainError, SecurityEvent, Severity

MAX_THRESHOLD = 100_000


class Rule(Protocol):
    """Contrat d'une règle : des événements en entrée, des alertes en sortie."""

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]: ...


def _checked_threshold(value: object) -> int:
    # bool est un sous-type de int : True passerait pour 1 et déclencherait une alerte par événement
    if isinstance(value, bool) or not isinstance(value, int):
        raise DomainError("seuil : un entier est attendu")
    if not 1 <= value <= MAX_THRESHOLD:
        raise DomainError(f"seuil hors de l'intervalle 1..{MAX_THRESHOLD}")
    return value


@dataclass(frozen=True, slots=True)
class BruteForceRule:
    threshold: int = 5

    def __post_init__(self) -> None:
        _checked_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        failures = Counter(e.source_ip for e in events if e.action == "login_failed")
        return [
            Alert("brute_force", ip, Severity.HIGH, f"{n} échecs de connexion depuis {ip}")
            for ip, n in failures.items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class PortScanRule:
    threshold: int = 20

    def __post_init__(self) -> None:
        _checked_threshold(self.threshold)

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        probes = Counter(e.source_ip for e in events if e.action == "port_probe")
        return [
            Alert("port_scan", ip, Severity.MEDIUM, f"{n} sondes de ports depuis {ip}")
            for ip, n in probes.items()
            if n >= self.threshold
        ]


@dataclass(frozen=True, slots=True)
class RuleSet:
    """Composite : un ensemble de règles se comporte comme une règle."""

    rules: tuple[Rule, ...]

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[Alert]:
        return [alert for rule in self.rules for alert in rule.evaluate(events)]


# Liste blanche explicite : le nom vient d'une config (donc d'une entrée non fiable),
# il ne sert qu'à CHERCHER dans ce dictionnaire, jamais à importer ou instancier dynamiquement.
_REGISTRY: Mapping[str, Callable[..., Rule]] = MappingProxyType(
    {"brute_force": BruteForceRule, "port_scan": PortScanRule}
)
_ALLOWED_KEYS = frozenset({"kind", "threshold"})


def build_rule(spec: Mapping[str, object]) -> Rule:
    """Fabrique une règle depuis un dictionnaire ; refuse tout ce qui n'est pas enregistré."""
    if not isinstance(spec, Mapping):
        raise DomainError("spécification de règle : un dictionnaire est attendu")
    if not set(spec) <= _ALLOWED_KEYS:
        raise DomainError("spécification de règle : clé inconnue")
    kind = spec.get("kind")
    if not isinstance(kind, str) or kind not in _REGISTRY:
        raise DomainError("type de règle inconnu")
    factory = _REGISTRY[kind]
    if "threshold" not in spec:
        return factory()
    return factory(_checked_threshold(spec["threshold"]))
