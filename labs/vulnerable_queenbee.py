# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import json
import os
import re
import sqlite3

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


def close_incident(user: str, incident_id: int) -> None:
    # FAILLE-5 : aucune vérification d'autorisation dans la couche service
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


def call_enrichment_service(ip: str) -> dict:
    # FAILLE-6 : appel inter-services sans authentification mutuelle (ni mTLS, ni jeton)
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str) -> bool:
    return token == _api_key()                        # FAILLE-7 : comparaison non constante (timing)
