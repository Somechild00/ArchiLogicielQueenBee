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

LAB_KEY = "k" * 40  # valeur de test, jamais une vraie clé


@pytest.fixture
def lab_key(monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv(vuln.ENV_API_KEY, LAB_KEY)
    return LAB_KEY


def _new_incident() -> int:
    cursor = vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.9', 'open')")
    assert cursor.lastrowid is not None
    return cursor.lastrowid


def _status(incident_id: int) -> str:
    row = vuln.conn.execute("SELECT status FROM incident WHERE id = ?", (incident_id,)).fetchone()
    return str(row[0])


def test_faille1_no_secret_in_code_and_refuses_to_start_without_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Test inversé : l'ancienne clé n'est plus dans le code et n'ouvre plus rien.
    assert "qb-admin-2026" not in inspect.getsource(vuln)
    monkeypatch.delenv(vuln.ENV_API_KEY, raising=False)
    with pytest.raises(RuntimeError, match="refus de démarrer"):
        vuln.check_token("qb-admin-2026")
    monkeypatch.setenv(vuln.ENV_API_KEY, "trop-courte")
    with pytest.raises(RuntimeError, match="refus de démarrer"):
        vuln.check_token("trop-courte")


def test_faille1_key_comes_from_environment(lab_key: str) -> None:
    assert vuln.check_token(lab_key)
    assert not vuln.check_token("qb-admin-2026")


def test_faille5_anyone_can_close_an_incident() -> None:
    incident_id = _new_incident()
    vuln.close_incident("visiteur-anonyme", incident_id)  # aucun rôle vérifié
    assert _status(incident_id) == "closed"


def test_faille6_internal_service_answers_without_authentication() -> None:
    # Le service ne demande aucune preuve d'identité : seul l'argument métier existe.
    assert list(inspect.signature(vuln.call_enrichment_service).parameters) == ["ip"]
    assert vuln.call_enrichment_service("10.0.0.1")["reputation"]


def test_faille7_token_comparison_is_not_constant_time(
    monkeypatch: pytest.MonkeyPatch, lab_key: str
) -> None:
    calls: list[tuple[object, object]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    vuln.check_token(lab_key)
    assert calls == []  # `==` s'arrête au premier caractère différent : fuite par le temps


def test_faille3_pickle_executes_code_on_load(capsys: pytest.CaptureFixture[str]) -> None:
    class Payload:  # charge utile INOFFENSIVE : un simple print
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (print, ("PWNED: code exécuté pendant la désérialisation",))

    vuln.receive_agent_message(pickle.dumps(Payload()))
    assert "PWNED" in capsys.readouterr().out  # la simple lecture a exécuté du code


def test_faille2_redos_is_gone() -> None:
    # Test inversé : la charge qui explosait (temps x16 pour +4 caractères) est rejetée
    # instantanément, même 1 000 fois plus longue.
    start = time.perf_counter()
    for n in (18, 22, 30, 50_000):
        assert not vuln.is_valid_username("a" * n + "!")
    assert time.perf_counter() - start < 0.1


@pytest.mark.parametrize("name", ["alice", "bob.smith", "svc_backup-01"])
def test_faille2_legit_usernames_still_accepted(name: str) -> None:
    assert vuln.is_valid_username(name)


def test_faille4_sql_injection_dumps_table() -> None:
    vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.1', 'open')")
    assert vuln.find_incidents("x' OR '1'='1")  # renvoie TOUTES les lignes
