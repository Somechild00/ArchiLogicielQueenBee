"""Filet de sécurité A2 : fige le comportement du script hérité AVANT de le refactorer.

On ne juge pas ici si le comportement est bon (il ne l'est pas) : on constate ce qu'il fait.
"""

import importlib.util
import smtplib
import types
from pathlib import Path

import pytest

LEGACY = Path(__file__).resolve().parent.parent / "legacy" / "log_watcher.py"


class FakeSMTP:
    sent: list[str] = []

    def __init__(self, host: str) -> None:
        self.host = host

    def login(self, user: str, password: str) -> None:
        return None

    def sendmail(self, sender: str, recipient: str, body: str) -> None:
        FakeSMTP.sent.append(body)


def load_legacy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> types.ModuleType:
    monkeypatch.chdir(tmp_path)  # le script crée incidents.db dans le dossier courant
    FakeSMTP.sent = []
    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    spec = importlib.util.spec_from_file_location("legacy_log_watcher", LEGACY)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.DB.execute("CREATE TABLE incidents (ip TEXT, user TEXT)")
    return module


def run_legacy(module: types.ModuleType, tmp_path: Path, lines: list[str]) -> None:
    log = tmp_path / "auth.log"
    log.write_text("\n".join(lines) + "\n", encoding="utf-8")
    module.LogWatcher(str(log)).run()


def test_legacy_five_failures_same_ip_raise_one_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_legacy(tmp_path, monkeypatch)
    run_legacy(module, tmp_path, ["Failed password for root from 10.0.0.1"] * 7)
    assert FakeSMTP.sent == ["Brute force from 10.0.0.1"]  # une seule alerte, au 5e échec
    assert module.DB.execute("SELECT ip, user FROM incidents").fetchall() == [("10.0.0.1", "root")]


def test_legacy_failures_spread_over_two_ips_raise_no_alert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_legacy(tmp_path, monkeypatch)
    lines = ["Failed password for root from 10.0.0.1"] * 4 + [
        "Failed password for root from 10.0.0.2"
    ] * 4
    run_legacy(module, tmp_path, lines)
    assert FakeSMTP.sent == []
    assert module.DB.execute("SELECT COUNT(*) FROM incidents").fetchone() == (0,)
