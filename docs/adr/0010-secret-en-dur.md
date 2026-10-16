# ADR 0010 — Correctif : Secret en dur partagé

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : configuration · **Propriété DICP** : C

## Contexte
Une clé écrite dans le code et partagée par tous se retrouve dans le dépôt, donc chez quiconque le lit.

## Décision
Lire la clé dans l'environnement (`.env` ignoré par Git, coffre en production), une clé par agent, échec explicite au démarrage si elle est absente ou trop courte.

## Conséquences
- Positive : la clé n'est plus dans le code ni dans l'historique du dépôt.
- **Négative** : l'ancienne clé commitée reste compromise : il faut la révoquer, la régénérer et la purger de l'historique.

## Preuve et non-régression
`labs/vulnerable_queenbee.py` : `_api_key()` lit `QUEENBEE_LAB_API_KEY` (≥ 32 caractères, sinon refus de démarrer). Tests : `tests/test_lab_vulnerable.py::test_faille1_no_secret_in_code_and_refuses_to_start_without_key`, `::test_faille1_key_comes_from_environment`. L'ancienne clé `qb-admin-2026` reste dans l'historique : elle est considérée comme révoquée.
