"""Entrées malveillantes aux ports d'entrée : chaque test vérifie le refus net (travail du J2)."""

import json
import string

import pytest
from hypothesis import given
from hypothesis import strategies as st

from queenbee.adapters.inbound.agent_api import (
    MAX_BODY_BYTES,
    UnauthenticatedError,
    parse_agent_message,
    sign,
)
from queenbee.adapters.inbound.threat_feed import ThreatFeedTranslator
from queenbee.domain.model import DomainError, SecurityEvent

KEY = bytes(range(32))
GOOD = {
    "source_ip": "10.0.0.66",
    "username": "root",
    "action": "login_failed",
    "timestamp": "2026-10-14T09:00:00+00:00",
}


def _body(event: dict[str, str]) -> bytes:
    return json.dumps(event).encode()


def test_tampered_field_after_signing_rejected() -> None:
    signature = sign(_body(GOOD), KEY)
    tampered = _body({**GOOD, "source_ip": "10.0.0.1"})  # la signature ne suit plus
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(tampered, signature, KEY)


def test_oversized_message_rejected_before_signature_check() -> None:
    body = b"{" + b" " * MAX_BODY_BYTES + b"}"
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


@pytest.mark.parametrize("body", [b"not json", b"[]", b'{"source_ip": 1}', b"\xff\xfe"])
def test_signed_garbage_rejected(body: bytes) -> None:
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


def test_signed_but_poisoned_username_rejected_by_domain() -> None:
    body = _body({**GOOD, "username": "root'; DROP TABLE incidents;--"})
    with pytest.raises(DomainError):
        parse_agent_message(body, sign(body, KEY), KEY)


def test_non_ascii_signature_is_refused_not_crashing() -> None:
    with pytest.raises(UnauthenticatedError):
        parse_agent_message(_body(GOOD), "é" * 64, KEY)


_text = st.text(alphabet=string.printable + "é" + chr(0x202E) + chr(0), max_size=80)


@given(_text, _text, _text, _text)
def test_hypothesis_signed_garbage_fields_are_rejected_or_valid(
    ip: str, user: str, action: str, ts: str
) -> None:
    """Même avec une signature valide, le domaine refuse les champs hostiles."""
    body = _body({"source_ip": ip, "username": user, "action": action, "timestamp": ts})
    try:
        event = parse_agent_message(body, sign(body, KEY), KEY)
    except DomainError:
        return
    assert isinstance(event, SecurityEvent)
    assert event.timestamp.tzinfo is not None


def test_threat_feed_rejects_unknown_risk_level() -> None:
    with pytest.raises(DomainError):
        ThreatFeedTranslator().translate({"indicator": "203.0.113.9", "risk_level": "extreme"})
