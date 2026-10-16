# ruff: noqa
"""VARIANTE VOLONTAIREMENT FRAGILE de Queen Bee — usage LABORATOIRE uniquement (J3-A1).

Sept failles d'architecture à exploiter (en local), corriger, puis vérifier avec bandit/pip-audit.
Chaque faille porte un numéro FAILLE-n ; la correction de référence est dans src/queenbee.
"""
import os
import pickle
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

USER_RE = re.compile(r"^([a-zA-Z0-9]+\s?)*$")       # FAILLE-2 : quantificateurs imbriqués -> ReDoS

conn = sqlite3.connect(":memory:")
conn.execute("CREATE TABLE incident (id INTEGER PRIMARY KEY, ip TEXT, status TEXT)")


def receive_agent_message(raw: bytes):
    return pickle.loads(raw)                          # FAILLE-3 : désérialisation non sûre (RCE)


def is_valid_username(name: str) -> bool:
    return USER_RE.match(name) is not None


def find_incidents(ip: str):
    # FAILLE-4 : injection SQL (f-string)
    return conn.execute(f"SELECT * FROM incident WHERE ip = '{ip}'").fetchall()


def close_incident(user: str, incident_id: int) -> None:
    # FAILLE-5 : aucune vérification d'autorisation dans la couche service
    conn.execute("UPDATE incident SET status='closed' WHERE id=?", (incident_id,))


def call_enrichment_service(ip: str) -> dict:
    # FAILLE-6 : appel inter-services sans authentification mutuelle (ni mTLS, ni jeton)
    return {"ip": ip, "reputation": "unknown"}


def check_token(token: str) -> bool:
    return token == _api_key()                        # FAILLE-7 : comparaison non constante (timing)
