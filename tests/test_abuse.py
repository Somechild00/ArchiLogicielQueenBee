"""Tests d'abus : on se met à la place de l'attaquant et on vérifie que le refus est net."""

from typing import Any

import pytest

from queenbee.config import ConfigError, SettingsBuilder
from queenbee.domain.model import Alert, DomainError, Severity
from queenbee.domain.rules import MAX_THRESHOLD, build_rule

GOOD_KEY = "k" * 32


@pytest.mark.parametrize("threshold", [0, -1, 5.0, "5", None, MAX_THRESHOLD + 1])
def test_abuse_invalid_threshold_is_rejected(threshold: Any) -> None:
    with pytest.raises(DomainError):
        build_rule({"kind": "brute_force", "threshold": threshold})


@pytest.mark.parametrize(
    "spec",
    [
        {"kind": "BRUTE_FORCE"},  # casse différente : pas de normalisation magique
        {"kind": ["brute_force"]},  # type non hashable
        {"kind": "brute_force", "callback": "os.system"},  # clé inattendue
        {"threshold": 5},  # pas de kind
        {},
    ],
)
def test_abuse_malformed_rule_spec_is_rejected(spec: Any) -> None:
    with pytest.raises(DomainError):
        build_rule(spec)


def test_abuse_rule_spec_that_is_not_a_dict_is_rejected() -> None:
    with pytest.raises(DomainError):
        build_rule("brute_force")  # type: ignore[arg-type]


def test_abuse_alert_message_cannot_be_unbounded() -> None:
    with pytest.raises(DomainError):
        Alert("r", "10.0.0.1", Severity.LOW, "x" * 10_000)


def test_abuse_builder_rejects_short_secret_without_leaking_it() -> None:
    with pytest.raises(ConfigError) as info:
        SettingsBuilder().with_secret_key("tropcourt").build()
    assert "tropcourt" not in str(info.value)


def test_abuse_builder_rejects_unknown_rule() -> None:
    builder = SettingsBuilder().with_secret_key(GOOD_KEY).with_rule({"kind": "os.system"})
    with pytest.raises(DomainError):
        builder.build()
