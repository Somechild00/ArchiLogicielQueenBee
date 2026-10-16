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

Les tests fournis par le formateur sont des spécifications et ne sont pas modifiés
(J1 : `tests/test_domain.py` + `tests/test_creational.py`, J2 : `tests/test_services.py` + `tests/test_adapters.py`,
J3 : `tests/test_lab_vulnerable.py`). Les autres fichiers de `tests/` sont les tests du groupe.

## Documentation (`docs/`)

| Pièce | Fichier |
|---|---|
| Modèle de menaces (actifs, DFD, STRIDE, exigences ↔ tests) | `docs/threat_model.md` |
| Relevé des problèmes du script hérité | `docs/refactoring_notes.md` |
| Décision d'architecture | `docs/adr/0001-architecture-hexagonale.md` |
| C4 niveau 1 (contexte) | `docs/c4/context.md` |
| Parcours « attaque détectée → incident clos » et tranche verticale | `docs/parcours.md` |
| Diagrammes UML (classes des patterns, séquence d'ingestion) | `docs/uml/` |

## Noms anglais dans le code, noms français sur les slides

Les slides montrent le code avec des noms français (`EvenementSecurite`, `RegleForceBrute`…) pour faciliter
la lecture. Ce dépôt garde les noms **anglais** (`SecurityEvent`, `BruteForceRule`…), comme en entreprise :
ce sont eux que les tests importent. La **fiche de correspondance français ↔ anglais** donne l'équivalence.

## Lancer sur un journal

```bash
export QUEENBEE_AGENT_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
python -c "from queenbee.bootstrap import main; main('auth.log')"
```
