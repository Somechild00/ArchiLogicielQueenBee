# Queen Bee — fil rouge du module BC3 · Architecture logicielle

**ITIS MAST CYBER 4 · ITIS MAST DEV 4** — tronc commun, 14, 15 et 16 octobre 2026

Mini-plateforme de détection : des **agents** (« abeilles ») remontent des événements de sécurité,
la **reine** les valide, détecte (règles), ouvre des **incidents** et alerte les analystes du SOC.

```
src/queenbee/
  domain/        # entités, objets-valeurs, règles métier — AUCUNE dépendance technique
  application/   # cas d'usage + ports (Protocol) + contrôle d'accès
  adapters/      # inbound (logs, API agents) / outbound (sqlite, notifiers, pare-feu)
  config.py      # Builder -> Settings figé ; secrets depuis l'environnement
  bootstrap.py   # composition root + Facade QueenBee
legacy/          # code de départ « Python Scripting Sécu » (MAUVAIS, à refactorer — J1)
labs/            # variante volontairement vulnérable (LABO uniquement — J3)
tests/           # pytest + hypothesis, tests d'abus inclus
```

## Démarrer (Python ≥ 3.12, recommandé 3.13)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env   # puis y coller une clé : python -c "import secrets; print(secrets.token_hex(32))"
make check          # = lint + types + tests + sécurité + architecture
```

Sous Windows (PowerShell, sans `make`) :

```powershell
python -m venv .venv ; .venv\Scripts\Activate.ps1 ; pip install -e ".[dev]"
ruff check . ; ruff format --check . ; mypy
python -m pytest --cov=src/queenbee --cov-fail-under=90
bandit -q -r src -c pyproject.toml ; pip-audit
$env:PYTHONPATH="src" ; lint-imports
```

## Portes qualité (toutes doivent être vertes avant un rendu)

| Commande | Rôle |
|---|---|
| `ruff check . && ruff format --check .` | style, bugs probables, règles sécurité `S` (bandit intégré) |
| `mypy` | typage strict |
| `pytest --cov=src/queenbee` | tests unitaires, d'abus, par propriétés |
| `bandit -r src -c pyproject.toml` | analyse statique sécurité |
| `pip-audit` | dépendances vulnérables (base PyPA / OSV) |
| `PYTHONPATH=src lint-imports` | contrat d'architecture : les couches ne s'inversent pas |

> `legacy/` et `labs/` contiennent du code **volontairement dangereux**. Ne jamais les déployer.

## Rendus

| Étiquette | Contenu |
|---|---|
| `j1-rendu` | Modèle de menaces STRIDE, refactoring SOLID du script hérité (`domain/`), patterns de création. Les fichiers du projet training (`pyproject.toml`, `Makefile`) n'étaient pas encore versionnés à cette date : ils ont été ajoutés au début du J2. |
| `j2-rendu` | Patterns défensifs, architecture hexagonale (ports et adaptateurs), ADR 0001, C4 de contexte, parcours, modèle de menaces mis à jour. 107 tests verts, couverture ≥ 90 %, `lint-imports` : 1 contrat respecté. |
| `j3-rendu` | 7 failles du laboratoire prouvées, corrigées et testées (ADR 0010 à 0016), infrastructure cible (ADR 0002 à 0006), dossier complet. 130 tests verts dont 26 `lab`, bandit, pip-audit et gitleaks propres. |

Les tests fournis par le formateur sont des spécifications et ne sont pas modifiés
(J1 : `tests/test_domain.py` + `tests/test_creational.py`, J2 : `tests/test_services.py` + `tests/test_adapters.py`).
Seule exception, demandée par la consigne du J3 : les preuves de `tests/test_lab_vulnerable.py` sont **inversées**
après correction. Les autres fichiers de `tests/` sont les tests du groupe.

## Dossier de conception sécurisée (`docs/`) — les 8 pièces

| Pièce | Fichier(s) |
|---|---|
| 1. Modèle de menaces (actifs, DFD, STRIDE, exigences, failles J3) | `docs/threat_model.md`, `docs/revue_securite.md` |
| 2. Code hexagonal testé | `src/queenbee/`, `tests/`, `docs/refactoring_notes.md` |
| 3. Traçabilité exigence ↔ test | `docs/tracabilite.md` |
| 4. ADR | `docs/adr/` (0001 architecture, 0002 à 0006 infrastructure, 0010 à 0016 correctifs) |
| 5. Infrastructure (zones, flux, secrets, journaux, sauvegarde) | `docs/infra/` |
| 6. Diagrammes (C4 niveaux 1 et 2, UML classes, séquence, composants) | `docs/c4/`, `docs/uml/`, `docs/parcours.md` |
| 7. Recette (Go / No-Go) | `docs/recette.md` |
| 8. Trace de release (écarts, dette) | `docs/release.md` |

## Noms anglais dans le code, noms français sur les slides

Les slides montrent le code avec des noms français (`EvenementSecurite`, `RegleForceBrute`…) pour faciliter
la lecture. Ce dépôt garde les noms **anglais** (`SecurityEvent`, `BruteForceRule`…), comme en entreprise :
ce sont eux que les tests importent. La **fiche de correspondance français ↔ anglais** donne l'équivalence.

## Lancer sur un journal

```bash
export QUEENBEE_AGENT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python -c "from queenbee.bootstrap import main; main('auth.log')"
```
