# ruff: noqa
"""Variante de LABORATOIRE de Queen Bee (J3-A1) — usage local uniquement.

Elle contenait sept failles d'architecture (FAILLE-1 à 7), prouvées puis corrigées une par une ;
chaque correctif est commenté sur place et couvert par tests/test_lab_vulnerable.py
(voir docs/revue_securite.md et les ADR 0010 à 0016).
"""
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sqlite3

from queenbee.application.access import WRITE_ROLES, require_role
from queenbee.application.errors import AccessDeniedError
from queenbee.domain.model import Principal

# FAILLE-1 corrigée : la clé vient de l'environnement (.env ignoré par Git, coffre en production),
# jamais du code ; absente ou trop courte, on refuse de démarrer.
ENV_API_KEY = "QUEENBEE_LAB_API_KEY"
MIN_KEY_LENGTH = 32


def _api_key() -> str:
    key = os.environ.get(ENV_API_KEY, "")
    if len(key) < MIN_KEY_LENGTH:
        raise RuntimeError(f"{ENV_API_KEY} absente ou trop courte : refus de démarrer")
    return key

# FAILLE-2 corrigée : longueur bornée AVANT la regex, classe simple sans quantificateur imbriqué,
# fullmatch (même règle que le domaine : src/queenbee/domain/model.py).
MAX_USERNAME_LENGTH = 64
USER_RE = re.compile(r"[A-Za-z0-9_.\-]{1,64}")

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE incident (id INTEGER PRIMARY KEY, ip TEXT, status TEXT)")


MAX_MESSAGE_BYTES = 4096
MESSAGE_FIELDS = frozenset({"source_ip", "username", "action", "timestamp"})


def receive_agent_message(raw: bytes) -> dict[str, str]:
    # FAILLE-3 corrigée : des DONNÉES (JSON), jamais du code (pickle) ; taille bornée, schéma exact.
    if not isinstance(raw, bytes) or len(raw) > MAX_MESSAGE_BYTES:
        raise ValueError("message trop volumineux")
    data = json.loads(raw)  # ValueError si ce n'est pas du JSON (un flux pickle, par exemple)
    if (
        not isinstance(data, dict)
        or set(data) != MESSAGE_FIELDS
        or not all(isinstance(value, str) for value in data.values())
    ):
        raise ValueError("schéma invalide")
    return data


def is_valid_username(name: str) -> bool:
    if not isinstance(name, str) or len(name) > MAX_USERNAME_LENGTH:
        return False
    return USER_RE.fullmatch(name) is not None


def find_incidents(ip: str) -> list[tuple[int, str, str]]:
    # FAILLE-4 corrigée : requête paramétrée, la donnée n'est jamais interprétée comme du SQL.
    return conn.execute("SELECT * FROM incident WHERE ip = ?", (ip,)).fetchall()


denied = 0  # refus comptés, jamais silencieux


def close_incident(principal: Principal, incident_id: int) -> None:
    # FAILLE-5 corrigée : autoriser D'ABORD (rôle analyst), puis vérifier, puis écrire.
    global denied
    try:
        require_role(principal, WRITE_ROLES)
    except AccessDeniedError:
        denied += 1
        raise
    if conn.execute("SELECT 1 FROM incident WHERE id = ?", (incident_id,)).fetchone() is None:
        raise LookupError("incident inconnu")
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


# FAILLE-6 corrigée : chaque appel inter-services porte un jeton signé (HMAC) à durée courte,
# avec une clé PROPRE au service (pas la clé d'administration), et l'appelant doit être connu.
ENV_SERVICE_KEY = "QUEENBEE_LAB_SERVICE_KEY"
SERVICE_TOKEN_TTL_S = 300
ALLOWED_CALLERS = frozenset({"queenbee-app"})
unauthenticated = 0  # appels refusés, comptés


def _service_key() -> bytes:
    key = os.environ.get(ENV_SERVICE_KEY, "")
    if len(key) < MIN_KEY_LENGTH:
        raise RuntimeError(f"{ENV_SERVICE_KEY} absente ou trop courte : refus de démarrer")
    return key.encode()


def _sign(payload: str) -> str:
    return hmac.new(_service_key(), payload.encode(), hashlib.sha256).hexdigest()


def issue_service_token(caller: str, now: float) -> str:
    payload = f"{caller}|{int(now) + SERVICE_TOKEN_TTL_S}"
    return f"{payload}|{_sign(payload)}"


def _authenticate(token: str, now: float) -> str:
    caller, _, rest = token.partition("|")
    expiry, _, signature = rest.partition("|")
    expected = _sign(f"{caller}|{expiry}")
    if not hmac.compare_digest(expected.encode(), signature.encode("utf-8", "replace")):
        raise PermissionError("jeton de service invalide")
    if not expiry.isdigit() or int(expiry) < now or caller not in ALLOWED_CALLERS:
        raise PermissionError("jeton de service invalide")
    return caller


def call_enrichment_service(ip: str, token: str, now: float) -> dict[str, str]:
    global unauthenticated
    try:
        _authenticate(token, now)
    except PermissionError:
        unauthenticated += 1
        raise
    ipaddress.ip_address(ip)  # ValueError si l'IP est piégée
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str) -> bool:
    # FAILLE-7 corrigée : comparaison en temps constant, sur des octets ; le jeton n'est jamais journalisé.
    if not isinstance(token, str):
        return False
    return hmac.compare_digest(token.encode("utf-8", "replace"), _api_key().encode())
