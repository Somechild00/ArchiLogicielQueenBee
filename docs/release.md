# Trace de release — Queen Bee 0.3.0 (`j3-rendu`, 16 octobre 2026)

## Contenu

- J1 : modèle de menaces STRIDE, domaine extrait du script hérité (SOLID), patterns de création.
- J2 : cinq patterns défensifs, architecture hexagonale (ADR 0001), C4 de contexte, parcours.
- J3 : sept failles du laboratoire prouvées, corrigées et testées (ADR 0010 à 0016), infrastructure cible
  (ADR 0002 à 0006), traçabilité, recette.

## Écarts par rapport à la cible

| Écart | Impact | Bloquant prod | Suite prévue |
| --- | --- | --- | --- |
| Persistance SQLite, pas PostgreSQL en zone Z3 (ADR 0006) | pas de sauvegarde continue ni d'isolation réseau de la base | oui | nouvel adaptateur du port `IncidentRepository` |
| Pas de passerelle, de mTLS ni de coffre réels : décrits dans `docs/infra/`, pas déployés | l'infrastructure est une cible, pas un livrable exécutable | oui | déploiement à outiller |
| Le correctif de la faille 6 est démontré par un jeton HMAC dans le laboratoire ; la cible est le mTLS | la preuve porte sur le principe, pas sur la configuration réseau | non | mTLS sur F3 et F4 |

## Dette assumée

- **Rejeu** d'un message d'agent signé : aucun nonce ni fenêtre de temps (risque accepté, modèle de menaces § 7).
- **Clé d'agent unique** partagée : une fuite compromet tous les agents (cible : une clé par agent, ADR 0004).
- **Limiteur d'alertes en mémoire** : état perdu au redémarrage, non partagé entre instances (ADR 0001).
- **Historique Git** : la clé de laboratoire `qb-admin-2026` et le mot de passe du script hérité y restent ;
  ce sont des valeurs d'exercice, considérées comme révoquées (ADR 0010).
- **`.gitleaksignore`** : un faux positif (`QUEENBEE_DB=queenbee.db` dans `.env.example`), vérifié à la main.
- **Suite de tests** : environ 2,8 s sans couverture (cible < 2 s), à cause des tests Hypothesis.
