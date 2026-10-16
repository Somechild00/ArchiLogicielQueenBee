# A2 — Parcours utilisateur : « attaque détectée » → « incident clos »

| # | Étape | Composante | Frontière franchie | Menace STRIDE | Parade |
| --- | --- | --- | --- | --- | --- |
| 1 | L'agent envoie un événement | Agent → adaptateur d'entrée | **Oui** (réseau) | **S**poofing : faux agent | Signature HMAC, comparaison en temps constant |
| 2 | Le message est lu et validé | SignedEventReader / LogLineAdapter | Non | **T**ampering, **D**oS : message énorme ou piégé | Taille bornée, schéma strict, validation du domaine, rejet compté |
| 3 | Les règles évaluent les événements | Domaine (RuleSet) | Non | **T**ampering : règle injectée | Factory à liste blanche (`build_rule`) |
| 4 | Un incident est créé et persisté | DetectionService → dépôt | **Oui** (base) | **T**ampering : injection SQL | Requêtes paramétrées |
| 5 | Le SOC est alerté | Notificateurs décorés | **Oui** (réseau) | **D**oS : inondation d'alertes ; **R**epudiation | RateLimitedNotifier, AuditedNotifier |
| 6 | L'analyste déplace l'incident | IncidentService | **Oui** (utilisateur) | **E**levation of privilege, **I**nfo disclosure | Rôle vérifié en premier, Proxy de lecture, message d'erreur générique |
| 7 | L'IP est bloquée (optionnel) | BlockIpCommand → pare-feu | **Oui** (système) | **T**ampering : commande piégée | IP validée avant exécution, annulation possible |
| 8 | L'incident est clos | Domaine (machine d'états) | Non | **R**epudiation, **T**ampering | Transition interdite refusée, journal d'audit |

## Tranche verticale choisie : « déplacer un incident »

| Axe | Contenu |
| --- | --- |
| Gestion | `IncidentService.move` : autoriser → vérifier → règle métier → persister |
| Contrat d'interface | Ports `IncidentRepository` (Protocol) ; entrée `Principal` + `UUID` + `IncidentStatus` |
| Persistance | `SqliteIncidentRepository` (prod), `InMemoryIncidentRepository` (tests) |
| Restitution | `IncidentReadProxy.list_open` pour les lecteurs |
| Recette | `tests/test_hexagon.py`, exécuté sur les deux dépôts |
