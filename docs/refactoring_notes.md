# Refactoring du script hérité — `legacy/log_watcher.py` (J1 · A2)

## 1. Filet de sécurité

`tests/test_characterization.py` fige le comportement du script **avant** toute modification :

1. 5 échecs depuis la même IP déclenchent **une seule** alerte (et un seul incident en base) ;
2. des échecs répartis sur 2 IP sous le seuil ne déclenchent rien.

## 2. Problèmes relevés

| # | Où (extrait du script) | Problème SOLID / sécurité | Conséquence | Correction |
|---|------------------------|---------------------------|-------------|------------|
| 1 | `SMTP_PASSWORD = "Sup3rS3cret!"` | Sécurité : secret en dur | Secret dans l'historique Git, donc compromis ; rotation obligatoire | `Secret` lu depuis l'environnement (`config.py`) |
| 2 | `f"INSERT INTO incidents VALUES ('{ip}', '{user}')"` | Sécurité : injection SQL (donnée du journal = donnée de l'attaquant) | Destruction ou vol de la base | Requête paramétrée (`SqliteIncidentRepository`) |
| 3 | `re.search(r"Failed password for (.*) from (.*)", line)` | Sécurité : regex non ancrée, `.*` gourmand | Capture de n'importe quoi, ReDoS possible, valeurs non validées | Regex ancrée et bornée + `SecurityEvent` validé (`log_parser.py`) |
| 4 | `class LogWatcher` lit, parse, détecte, stocke, alerte | **S** (responsabilité unique) : God class | Impossible à tester ou à changer sans tout casser | Domaine / application / adaptateurs séparés |
| 5 | `report()` : un `elif` par format | **O** (ouvert/fermé) | Chaque nouveau format modifie la classe existante | Une stratégie par format (non demandé au J1, noté pour la suite) |
| 6 | `DB = sqlite3.connect(...)` et `smtplib.SMTP(...)` créés en dur | **D** (inversion de dépendances) | Dépendance directe aux détails, tests impossibles sans vrai SQLite/SMTP | Ports `Protocol` (`IncidentRepository`, `Notifier`) injectés |
| 7 | `DB` global au module | État global / Singleton implicite | Tests qui se polluent, concurrence | Plus d'état global : objets créés dans `bootstrap.build_service` |
| 8 | `for line in open(self.path)` | Sécurité / robustesse : fichier jamais fermé, ligne et fichier sans limite | Fuite de descripteurs, saturation mémoire (D) | `with` + lecture bornée (`read_events`) |
| 9 | `self.counts[ip] == 5` | Seuil magique en dur (et `==` : ne se redéclenche jamais) | Règle non configurable, non testable | `BruteForceRule(threshold)` validé |
| 10 | `report("html")` concatène `k:v` brut | Sécurité : XSS | Script injecté via une « IP » | À traiter avec le rendu des rapports (échappement) |
| 11 | `alert()` : `login` sans TLS, texte brut dans `sendmail` | Sécurité : identifiants en clair sur le réseau | Interception du mot de passe SMTP | `starttls()` + `EmailMessage` (`SmtpNotifier`) |

## 3. Plan de commits (un commit par étape, jamais refactoring + correction mélangés)

1. `test: caractérisation du script hérité (5 échecs même IP)`
2. `docs: modèle de menaces STRIDE (A1)` *(peut venir avant, à toi de voir)*
3. `refactor: extraire SecurityEvent, Alert, Incident dans domain/model`
4. `refactor: extraire les règles (Strategy, Composite, Factory) dans domain/rules`
5. `refactor: définir les ports IncidentRepository et Notifier`
6. `refactor: adaptateurs SQLite/mémoire/SMTP et DetectionService`
7. `fix: requête SQL paramétrée`
8. `fix: secret SMTP lu dans l'environnement`
9. `fix: regex ancrée et lecture de journal bornée`
10. `feat: Builder de configuration, secret masqué`
11. `feat: Abstract Factory (production / mémoire) et Prototype revalidé`
12. `refactor: supprimer le Singleton, démarrage unique (bootstrap)`
13. `test: tests d'abus (seuils, spécifications malformées, secrets)`
