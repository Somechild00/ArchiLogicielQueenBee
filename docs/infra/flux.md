# Matrice des flux

STRIDE : **S**poofing, **T**ampering, **R**epudiation, **I**nformation disclosure, **D**enial of service, **E**levation of privilege.

| # | Source | Destination | Protocole / port | Élément d'architecture qui le justifie | STRIDE traité | Parade |
| --- | --- | --- | --- | --- | --- | --- |
| F1 | Agents (Z0) | Passerelle (Z1) | HTTPS 443 | Adaptateur d'entrée signé (`parse_agent_message`) | S, T, D | TLS + signature HMAC, taille bornée, débit limité |
| F2 | Analystes / lecteurs (Z0) | Passerelle (Z1) | HTTPS 443 | Cas d'usage `IncidentService` + `IncidentReadProxy` | S, E | authentification forte, rôle vérifié en premier |
| F3 | Passerelle (Z1) | Application (Z2) | mTLS 8443 | Port d'entrée de l'application | S, T | certificats mutuels, un seul appelant autorisé |
| F4 | Application (Z2) | Base (Z3) | TLS 5432 | Port `IncidentRepository` | T, I | compte applicatif à droits minimaux, requêtes paramétrées |
| F5 | Application (Z2) | Collecteur (Z4) | syslog TLS 6514 | Décorateur `AuditedNotifier` + journal d'audit | R | écriture seule, sans droit de lecture ni de suppression |
| F6 | Passerelle (Z1) | Collecteur (Z4) | syslog TLS 6514 | Journalisation des rejets | R | idem F5 |
| F7 | Base (Z3) | Collecteur (Z4) | syslog TLS 6514 | Journal d'accès à la base | R | idem F5 |
| F8 | Application (Z2) | Coffre (Z4) | HTTPS 8200 | Racine de composition (`bootstrap.py`, `settings_from_env`) | I | jeton à durée courte, secrets lus au démarrage seulement |
| F9 | Application (Z2) | Relais de notification (externe) | SMTPS 587 ou HTTPS 443 | Port `Notifier` + `RateLimitedNotifier` | D, I | sortie via proxy sortant, limitation de débit, aucun secret dans le message |
| F10 | Application (Z2) | API pare-feu (externe) | HTTPS 443 | Port `Firewall` + `BlockIpCommand` | T, E | compte de service restreint, IP validée avant envoi, blocage annulable |
| F11 | Base (Z3) | Stockage de sauvegardes (Z4) | HTTPS 443 (envoi seul) | Sauvegarde et reprise | I, D | chiffrement, stockage immuable, la base ne peut pas supprimer |
| F12 | Postes d'administration (Z5) | Bastion (Z5) | SSH 22 | Zone d'administration | S, E | clé + MFA, comptes nominatifs |
| F13 | Bastion (Z5) | Passerelle, application, base | SSH 22 | Zone d'administration | E, R | sessions journalisées vers F5, accès limité dans le temps |
| **F∞** | **Toutes** | **Toutes** | **tous** | Défaut : **tout le reste est refusé** | tous | règle finale « deny all » sur chaque zone |

**Contrôles de cohérence**
- Aucun flux sans élément d'architecture (colonne 5) : vérifié ligne par ligne.
- Aucun composant sans flux : agents (F1), utilisateurs (F2), passerelle (F1 à F3, F6), application (F3 à F10), base (F4, F7, F11), collecteur (F5 à F7), coffre (F8), sauvegardes (F11), bastion (F12, F13), relais et pare-feu (F9, F10).
