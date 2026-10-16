# Diagramme de composants — les dépendances pointent vers le centre

Le sens des flèches est vérifié par `lint-imports` (contrat de couches dans `pyproject.toml`).

```mermaid
flowchart TB
    boot["queenbee.bootstrap\nracine de composition, façade QueenBee"]
    cfg["queenbee.config / factories\nBuilder, Secret, fabriques"]
    subgraph adapters["queenbee.adapters"]
        inb["inbound\nagent_api · log_parser · threat_feed"]
        outb["outbound\nrepositories · notifiers · response"]
    end
    subgraph application["queenbee.application"]
        svc["services\nDetectionService · IncidentService"]
        acc["access\nrequire_role · IncidentReadProxy"]
        ports["ports (Protocol)\nIncidentRepository · Notifier · Firewall"]
    end
    domain["queenbee.domain\nmodel · rules (aucune dépendance technique)"]

    boot --> cfg
    boot --> adapters
    boot --> application
    inb --> domain
    outb -. "implémente" .-> ports
    outb --> domain
    svc --> ports
    svc --> acc
    svc --> domain
    acc --> domain
    ports --> domain
```

Diagrammes associés : classes (`docs/uml/patterns.md`), séquence d'ingestion (`docs/uml/sequence_ingest.puml`),
C4 niveaux 1 et 2 (`docs/c4/`).
