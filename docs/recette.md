# Recette — décision Go / No-Go (16 octobre 2026)

Contrôles exécutés sous Python 3.13 sur la version étiquetée `j3-rendu`.

| # | Critère | Attendu | Résultat | Statut |
| --- | --- | --- | --- | --- |
| 1 | `ruff check .` et `ruff format --check .` | aucune erreur | « All checks passed! » | ✅ |
| 2 | `mypy` (strict) | aucune erreur | aucune erreur | ✅ |
| 3 | `pytest --cov=src/queenbee --cov-fail-under=90` | tout vert, ≥ 90 % | 130 tests verts, 99 % | ✅ |
| 4 | Tests fournis par le formateur (J1, J2, J3) | verts, non modifiés (sauf inversion demandée au J3) | verts | ✅ |
| 5 | `pytest -m lab` | 7 failles prouvées puis corrigées | 26 tests verts | ✅ |
| 6 | `bandit` sur `src` et `labs` | aucune alerte Medium ou High | aucune alerte | ✅ |
| 7 | `pip-audit` | aucune dépendance vulnérable | aucune | ✅ |
| 8 | `lint-imports` | 1 contrat respecté, 0 cassé | 1 respecté, 0 cassé | ✅ |
| 9 | `gitleaks detect` sur tout l'historique | aucun secret | aucun (1 faux positif justifié) | ✅ |
| 10 | Exigences EX-01 à EX-08 et menaces J2/J3 | chacune liée à un test vert | voir `docs/tracabilite.md` | ✅ |
| 11 | Dossier : 8 pièces dans `docs/` | présentes | présentes | ✅ |

## Décision : **GO** pour une démonstration en environnement de test

**No-Go pour une production réelle** tant que les écarts de `docs/release.md` marqués « bloquant prod »
ne sont pas traités (PostgreSQL en zone Z3, protection contre le rejeu, clé par agent).
