# C4 — Niveau 2 : conteneurs et frontières de confiance

```mermaid
flowchart LR
    agent["Agent (abeille)\nZ0 non fiable"]
    analyst["Analyste SOC / lecteur\nZ0 non fiable"]

    subgraph Z1["Z1 · DMZ"]
        gw["Passerelle d'entrée\nTLS, limitation de débit"]
    end
    subgraph Z2["Z2 · Application Queen Bee"]
        api["Adaptateurs d'entrée\nagent_api (HMAC), log_parser"]
        core["Cœur hexagonal\ndomain + application"]
        out["Adaptateurs de sortie\ndépôt, notificateurs, pare-feu"]
    end
    subgraph Z3["Z3 · Données"]
        db[("Base des incidents\nSQLite (dev) / PostgreSQL (cible)")]
    end
    subgraph Z4["Z4 · Sécurité"]
        vault["Coffre à secrets"]
        logs["Collecteur de journaux\n(ajout seul)"]
    end
    notif["Relais de notification SOC\n(externe)"]
    fw["API pare-feu\n(externe)"]

    agent -- "F1 HTTPS, message signé HMAC" --> gw
    analyst -- "F2 HTTPS, authentification + rôle" --> gw
    gw -- "F3 mTLS" --> api
    api --> core
    core --> out
    out -- "F4 TLS, requêtes paramétrées" --> db
    out -- "F5 syslog TLS, écriture seule" --> logs
    vault -- "F8 secrets au démarrage" --> core
    out -- "F9 alertes limitées en débit" --> notif
    out -- "F10 blocage d'IP validé, annulable" --> fw
```

Frontières : Z0 → Z1 (tout est hostile), Z1 → Z2 (mTLS), Z2 → Z3 (compte à droits minimaux),
Z2 → Z4 (écriture seule), Z2 → externe (sortie filtrée). Détail des flux : `docs/infra/flux.md`.
