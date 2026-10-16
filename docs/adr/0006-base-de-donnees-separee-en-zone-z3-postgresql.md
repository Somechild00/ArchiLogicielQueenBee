# ADR 0006 — Base de données séparée en zone Z3 (PostgreSQL)

- **Statut** : accepté
- **Date** : 16 octobre 2026
- **Décideurs** : Khady, Amale

## Contexte
En développement la persistance est sqlite ; en production, l'isolation et la sauvegarde continue exigent un serveur dédié.

## Décision
Cible : PostgreSQL en zone Z3, accessible seulement depuis l'application ; un nouvel adaptateur de sortie implémente le port `IncidentRepository`.

## Conséquences
- Positive : grâce à l'architecture hexagonale, seul l'adaptateur change, pas le domaine ni les cas d'usage.
- **Négative** : migration à écrire et à tester, plus un composant de plus à exploiter ; cette étape n'est pas réalisée dans le code actuel (dette assumée, à noter dans la trace de release).
