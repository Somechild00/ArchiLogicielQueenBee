# A2 — Infrastructure cible : zones de confiance

Une zone = un niveau de confiance. On ne passe d'une zone à l'autre que par un flux déclaré
dans `flux.md` ; tout le reste est refusé.

```mermaid
flowchart TB
    subgraph Z0["Z0 · Non fiable (agents, postes analystes)"]
        agents["Agents / sources de journaux"]
        users["Analystes SOC et lecteurs"]
    end
    subgraph Z1["Z1 · DMZ"]
        gw["Passerelle d'entrée\n(TLS, limitation de débit)"]
    end
    subgraph Z2["Z2 · Application"]
        app["Queen Bee\n(adaptateurs d'entrée, cas d'usage)"]
    end
    subgraph Z3["Z3 · Données"]
        db[("PostgreSQL")]
    end
    subgraph Z4["Z4 · Sécurité (journaux, secrets, sauvegardes)"]
        logs["Collecteur de journaux\n(append-only)"]
        vault["Coffre à secrets"]
        bkp["Stockage de sauvegardes\n(immuable)"]
    end
    subgraph Z5["Z5 · Administration"]
        bastion["Bastion (MFA)"]
        admin["Postes d'administration"]
    end
    ext["Services externes :\nrelais de notification, API pare-feu"]

    agents -->|F1| gw
    users -->|F2| gw
    gw -->|F3| app
    app -->|F4| db
    app -->|F5| logs
    gw -->|F6| logs
    db -->|F7| logs
    app -->|F8| vault
    app -->|F9| ext
    app -->|F10| ext
    db -->|F11| bkp
    admin -->|F12| bastion
    bastion -->|F13| app
    bastion -->|F13| db
    bastion -->|F13| gw
```

| Zone | Contenu | Niveau de confiance | Règle d'or |
| --- | --- | --- | --- |
| Z0 | agents, postes des utilisateurs | nul : tout est hostile | on ne fait confiance à rien de ce qui en vient (signature + validation) |
| Z1 | passerelle d'entrée | faible | termine le TLS, limite le débit, ne contient aucune donnée |
| Z2 | application Queen Bee | moyen | n'accepte que la passerelle et le bastion |
| Z3 | base de données | élevé | n'accepte que l'application (+ bastion pour l'administration) |
| Z4 | journaux, secrets, sauvegardes | très élevé | l'application y écrit mais ne peut ni relire ni effacer |
| Z5 | bastion, postes admin | très élevé | seul chemin d'administration, authentification forte |
