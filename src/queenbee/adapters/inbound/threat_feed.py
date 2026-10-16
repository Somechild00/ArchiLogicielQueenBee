"""Couche anti-corruption : un flux de menaces externe (confiance faible) -> NOTRE modèle."""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from queenbee.domain.model import DomainError

_RISK: Mapping[str, int] = MappingProxyType({"low": 20, "medium": 50, "high": 80, "critical": 100})


@dataclass(frozen=True, slots=True)
class ThreatIndicator:
    ip: str
    score: int  # 0..100


class ThreatFeedTranslator:
    """Traduit, valide, isole : ce qui ne se vérifie pas est refusé."""

    def translate(self, raw: Mapping[str, object]) -> ThreatIndicator:
        ip = raw.get("indicator")
        risk = raw.get("risk_level")
        if not isinstance(ip, str) or not isinstance(risk, str) or risk not in _RISK:
            raise DomainError("indicateur externe invalide")
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise DomainError("indicateur externe invalide") from exc
        return ThreatIndicator(ip=ip, score=_RISK[risk])
