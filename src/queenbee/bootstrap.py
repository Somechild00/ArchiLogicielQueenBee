"""Point de démarrage unique : crée les objets et les passe explicitement (plus de Singleton)."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path

from queenbee.adapters.inbound.log_parser import read_events
from queenbee.application.services import DetectionService
from queenbee.config import Settings, read_env_file, settings_from_env
from queenbee.domain.ports import Notifier
from queenbee.domain.rules import RuleSet
from queenbee.factories import ComponentFactory, ProdFactory


def build_service(settings: Settings, factory: ComponentFactory | None = None) -> DetectionService:
    """Assemble le service. Chaque appel crée de nouveaux objets : aucun état global."""
    notifiers: list[Notifier]
    if factory is None:
        factory = ProdFactory(settings.db_path, settings.smtp)
        notifiers = [factory.notifier()] if settings.smtp is not None else []
    else:
        notifiers = [factory.notifier()]
    components = factory
    return DetectionService(RuleSet(settings.rules), components.repository(), notifiers)


def main(log_path: str, env: Mapping[str, str] | None = None) -> int:
    merged = {**read_env_file(Path(".env")), **(env if env is not None else os.environ)}
    service = build_service(settings_from_env(merged))
    events = list(read_events(Path(log_path)))
    alerts = service.ingest(events)
    print(f"{len(events)} événements analysés, {len(alerts)} alerte(s)")
    return 0
