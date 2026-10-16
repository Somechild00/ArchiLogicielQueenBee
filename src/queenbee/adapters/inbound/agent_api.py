"""Port d'entrée « API des agents » : message borné, signé (HMAC-SHA256), schéma strict.

Ordre des contrôles : 1. taille, 2. qui ? (signature, comparaison en temps constant),
3. données (JSON, jamais pickle), 4. schéma exact, 5. le domaine revalide.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime

from queenbee.domain.model import DomainError, SecurityEvent

MAX_BODY_BYTES = 4096
_FIELDS = frozenset({"source_ip", "username", "action", "timestamp"})


class UnauthenticatedError(Exception):
    """Signature absente ou fausse : on ne sait pas qui parle, on ne lit pas."""


def sign(body: bytes, key: bytes) -> str:
    """Côté agent : signature hexadécimale du corps du message."""
    return hmac.new(key, body, hashlib.sha256).hexdigest()


def parse_agent_message(body: bytes, signature: str, key: bytes) -> SecurityEvent:
    if not isinstance(body, bytes) or len(body) > MAX_BODY_BYTES:  # 1. taille
        raise DomainError("message trop volumineux")
    if not isinstance(signature, str) or not hmac.compare_digest(  # 2. qui ?
        sign(body, key).encode(), signature.encode("utf-8", "replace")
    ):
        raise UnauthenticatedError("signature HMAC invalide")
    try:
        data = json.loads(body)  # 3. données
    except (ValueError, RecursionError) as exc:
        raise DomainError("JSON invalide") from exc
    if (  # 4. schéma exact : aucun champ en trop, aucun en moins, que des chaînes
        not isinstance(data, dict)
        or set(data) != _FIELDS
        or not all(isinstance(value, str) for value in data.values())
    ):
        raise DomainError("schéma invalide")
    try:
        timestamp = datetime.fromisoformat(data["timestamp"])
    except ValueError as exc:
        raise DomainError("horodatage invalide") from exc
    return SecurityEvent(data["source_ip"], data["username"], data["action"], timestamp)  # 5.
