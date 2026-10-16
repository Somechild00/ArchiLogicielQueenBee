# Diagramme de classes — patterns défensifs

```mermaid
classDiagram
    class Notifier {
        <<Protocol>>
        +notify(alert)
    }
    class RateLimitedNotifier { +dropped : int }
    class AuditedNotifier
    class FanOutNotifier { +failures : int }
    Notifier <|.. RateLimitedNotifier
    Notifier <|.. AuditedNotifier
    Notifier <|.. FanOutNotifier
    RateLimitedNotifier o-- Notifier : décore
    AuditedNotifier o-- Notifier : décore
    FanOutNotifier o-- "0..*" Notifier : abonnés

    class IncidentReader {
        <<Protocol>>
        +get(id)
        +list_open()
    }
    class IncidentRepository {
        <<Protocol>>
        +save(incident)
    }
    class IncidentReadProxy { +denied : int }
    IncidentReader <|.. IncidentReadProxy
    IncidentReader <|-- IncidentRepository
    IncidentReadProxy o-- IncidentReader : protège

    class log_parser { <<module>> +parse_sshd_line(line) +read_lines(path) }
    class agent_api { <<module>> +parse_agent_message(body, signature, key) +sign(body, key) }
    class QueenBee { <<Façade>> +rejected : int +ingest_lines(lines) }
    log_parser ..> SecurityEvent : produit (Adaptateur)
    agent_api ..> SecurityEvent : produit (Adaptateur)
    QueenBee ..> log_parser : compte chaque rejet

    class Incident { +id +status +transition_to(target) }
    class IncidentStatus { <<enumeration>> OPEN TRIAGED CONTAINED CLOSED }
    Incident --> IncidentStatus : État

    class Command { <<Protocol>> +execute() +undo() }
    class BlockIpCommand
    class CommandHistory { +run(cmd) +undo_last() }
    Command <|.. BlockIpCommand
    CommandHistory o-- "0..*" Command
```
