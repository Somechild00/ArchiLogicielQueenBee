"""Command : blocage d'IP annulable. L'IP est validée avant toute exécution."""

from __future__ import annotations

import ipaddress
from typing import Protocol

from queenbee.application.ports import Firewall


class InMemoryFirewall:
    def __init__(self) -> None:
        self.blocked: set[str] = set()

    def block(self, ip: str) -> None:
        self.blocked.add(ip)

    def unblock(self, ip: str) -> None:
        self.blocked.discard(ip)


class Command(Protocol):
    def execute(self) -> None: ...
    def undo(self) -> None: ...


class BlockIpCommand:
    def __init__(self, firewall: Firewall, ip: str) -> None:
        ipaddress.ip_address(ip)  # ValueError si piégée : "... does not appear to be ..."
        self._firewall, self._ip = firewall, ip

    def execute(self) -> None:
        self._firewall.block(self._ip)

    def undo(self) -> None:
        self._firewall.unblock(self._ip)


class CommandHistory:
    def __init__(self) -> None:
        self._done: list[Command] = []

    def run(self, command: Command) -> None:
        command.execute()
        self._done.append(command)

    def undo_last(self) -> bool:
        if not self._done:
            return False
        self._done.pop().undo()
        return True
