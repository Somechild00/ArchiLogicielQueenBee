"""Jour 3 — démonstrations d'exploitation SUR LA VARIANTE DE LABORATOIRE (labs/).

Chaque test PROUVE la faille. Après correction, l'étudiant inverse l'assertion.
"""

import hmac
import inspect
import pickle
import time

import pytest

from labs import vulnerable_queenbee as vuln

pytestmark = pytest.mark.lab


def _new_incident() -> int:
    cursor = vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.9', 'open')")
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def _status(incident_id: int) -> str:
    row = vuln.conn.execute("SELECT status FROM incident WHERE id = ?", (incident_id,)).fetchone()
    return str(row[0])


def test_faille1_hardcoded_shared_secret_opens_the_door() -> None:
    # Il suffit de lire le dépôt pour connaître la clé, et elle ouvre tous les services.
    assert '"qb-admin-2026"' in inspect.getsource(vuln)
    assert vuln.check_token("qb-admin-2026")


def test_faille5_anyone_can_close_an_incident() -> None:
    incident_id = _new_incident()
    vuln.close_incident("visiteur-anonyme", incident_id)  # aucun rôle vérifié
    assert _status(incident_id) == "closed"


def test_faille6_internal_service_answers_without_authentication() -> None:
    # Le service ne demande aucune preuve d'identité : seul l'argument métier existe.
    assert list(inspect.signature(vuln.call_enrichment_service).parameters) == ["ip"]
    assert vuln.call_enrichment_service("10.0.0.1")["reputation"]


def test_faille7_token_comparison_is_not_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    vuln.check_token("qb-admin-2026")
    assert calls == []  # `==` s'arrête au premier caractère différent : fuite par le temps


def test_faille3_pickle_executes_code_on_load(capsys: pytest.CaptureFixture[str]) -> None:
    class Payload:  # charge utile INOFFENSIVE : un simple print
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (print, ("PWNED: code exécuté pendant la désérialisation",))

    vuln.receive_agent_message(pickle.dumps(Payload()))
    assert "PWNED" in capsys.readouterr().out  # la simple lecture a exécuté du code


def test_faille2_redos_is_exponential() -> None:
    def cost(n: int) -> float:
        t = time.perf_counter()
        vuln.is_valid_username("a" * n + "!")
        return time.perf_counter() - t

    assert cost(22) > 4 * cost(18)  # +4 caractères => temps x16 en théorie


def test_faille4_sql_injection_dumps_table() -> None:
    vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.1', 'open')")
    assert vuln.find_incidents("x' OR '1'='1")  # renvoie TOUTES les lignes
