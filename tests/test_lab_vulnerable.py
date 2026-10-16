"""Jour 3 — démonstrations d'exploitation SUR LA VARIANTE DE LABORATOIRE (labs/).

Chaque test PROUVE la faille. Après correction, l'étudiant inverse l'assertion.
"""

import hmac
import inspect
import pickle
import time
from collections.abc import Callable

import pytest

from labs import vulnerable_queenbee as vuln
from queenbee.application.errors import AccessDeniedError
from queenbee.domain.model import Principal

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


@pytest.mark.parametrize("roles", [frozenset(), frozenset({"viewer"})])
def test_faille5_without_analyst_role_cannot_close(roles: frozenset[str]) -> None:
    incident_id = _new_incident()
    before = vuln.denied
    with pytest.raises(AccessDeniedError):
        vuln.close_incident(Principal("visiteur-anonyme", roles), incident_id)
    assert _status(incident_id) == "open"  # test inversé : aucun effet de bord
    assert vuln.denied == before + 1  # le refus est compté


def test_faille5_analyst_can_close() -> None:
    incident_id = _new_incident()
    vuln.close_incident(Principal("alice", frozenset({"analyst"})), incident_id)
    assert _status(incident_id) == "closed"
    with pytest.raises(LookupError):
        vuln.close_incident(Principal("alice", frozenset({"analyst"})), 999_999)


NOW = 1_800_000_000.0  # horloge injectée : aucun time.sleep


@pytest.fixture
def service_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(vuln.ENV_SERVICE_KEY, "s" * 40)


def test_faille6_service_requires_a_token() -> None:
    assert "token" in inspect.signature(vuln.call_enrichment_service).parameters


@pytest.mark.usefixtures("service_key")
def test_faille6_valid_token_is_served() -> None:
    token = vuln.issue_service_token("queenbee-app", NOW)
    assert vuln.call_enrichment_service("10.0.0.1", token, NOW)["reputation"]


@pytest.mark.usefixtures("service_key")
@pytest.mark.parametrize(
    "make_token",
    [
        lambda: "",  # aucun jeton
        lambda: "queenbee-app|9999999999|" + "0" * 64,  # signature forgée
        lambda: vuln.issue_service_token("queenbee-app", NOW - 3600),  # jeton expiré
        lambda: vuln.issue_service_token("poste-inconnu", NOW),  # appelant non autorisé
        lambda: vuln.issue_service_token("queenbee-app", NOW).replace("app|", "app|9"),  # modifié
    ],
)
def test_faille6_unauthenticated_calls_refused_and_counted(make_token: Callable[[], str]) -> None:
    token = make_token()
    before = vuln.unauthenticated
    with pytest.raises(PermissionError):
        vuln.call_enrichment_service("10.0.0.1", token, NOW)
    assert vuln.unauthenticated == before + 1


def test_faille6_refuses_to_start_without_service_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(vuln.ENV_SERVICE_KEY, raising=False)
    with pytest.raises(RuntimeError, match="refus de démarrer"):
        vuln.issue_service_token("queenbee-app", NOW)


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


def test_faille3_pickle_payload_is_refused_without_running_code(
    capsys: pytest.CaptureFixture[str],
) -> None:
    class Payload:  # charge utile INOFFENSIVE : un simple print
        def __reduce__(self) -> tuple[object, tuple[str]]:
            return (print, ("PWNED: code exécuté pendant la désérialisation",))

    with pytest.raises(ValueError):
        vuln.receive_agent_message(pickle.dumps(Payload()))
    assert "PWNED" not in capsys.readouterr().out  # test inversé : rien n'a été exécuté


@pytest.mark.parametrize(
    "raw",
    [
        b"[]",
        b'{"source_ip": "10.0.0.1"}',
        b'{"source_ip": "10.0.0.1", "username": "root", "action": "login_failed",'
        b' "timestamp": "2026-10-16T09:00:00+00:00", "is_admin": "true"}',
        b"{" + b" " * 5000 + b"}",
    ],
)
def test_faille3_bad_messages_rejected(raw: bytes) -> None:
    with pytest.raises(ValueError):
        vuln.receive_agent_message(raw)


def test_faille3_valid_json_message_accepted() -> None:
    raw = (
        b'{"source_ip": "10.0.0.1", "username": "root", "action": "login_failed",'
        b' "timestamp": "2026-10-16T09:00:00+00:00"}'
    )
    assert vuln.receive_agent_message(raw)["username"] == "root"


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


def test_faille4_sql_injection_no_longer_dumps_table() -> None:
    vuln.conn.execute("INSERT INTO incident (ip, status) VALUES ('10.0.0.1', 'open')")
    assert vuln.find_incidents("x' OR '1'='1") == []  # test inversé : l'injection ne renvoie rien
    assert vuln.find_incidents("10.0.0.1")  # la recherche légitime marche toujours
    vuln.find_incidents("x'; DROP TABLE incident;--")
    assert vuln.find_incidents("10.0.0.1")  # la table existe encore
