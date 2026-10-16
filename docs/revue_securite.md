# A1 — Revue de sécurité de la variante fragile (`labs/vulnerable_queenbee.py`)

Cadre : exploitation **uniquement** sur `labs/vulnerable_queenbee.py`, en local (art. 323-1 et suivants du Code pénal).

Cycle suivi pour chaque faille : ① preuve (`@pytest.mark.lab`) → ② correctif **dans la couche d'origine** →
③ test inversé (non-régression) → ④ `bandit` et `pip-audit` → ⑤ ADR + modèle de menaces.
Aucune « rustine » : aucun `try/except` n'avale d'erreur ; chaque refus lève une exception et est compté.

| # | Faille | Couche | DICP | ① Preuve | ② Correctif | ③ Test inversé (`tests/test_lab_vulnerable.py`) | ⑤ ADR |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | Secret en dur partagé | configuration | C | écrite | clé lue dans l'environnement, refus de démarrer sans clé | `test_faille1_no_secret_in_code_and_refuses_to_start_without_key` | 0010 |
| 2 | ReDoS | adaptateur | D | fournie | longueur bornée, regex sans imbrication, `fullmatch` | `test_faille2_redos_is_gone` | 0011 |
| 3 | Désérialisation pickle | adaptateur | I | fournie | JSON borné, schéma exact | `test_faille3_pickle_payload_is_refused_without_running_code` | 0012 |
| 4 | SQL par f-string | persistance | I | fournie | requête paramétrée | `test_faille4_sql_injection_no_longer_dumps_table` | 0013 |
| 5 | Aucune autorisation | application | C · I | écrite | `require_role` en premier, refus compté | `test_faille5_without_analyst_role_cannot_close` | 0014 |
| 6 | Services non authentifiés | infrastructure | I · P | écrite | jeton HMAC à durée courte, clé propre au service | `test_faille6_unauthenticated_calls_refused_and_counted` | 0015 |
| 7 | Comparaison de jeton non constante | sécurité | C | écrite | `hmac.compare_digest` sur des octets | `test_faille7_token_comparison_is_constant_time` | 0016 |

Historique Git : un commit `test:` pour les preuves, puis un commit `fix:` par faille (correctif + test inversé).

## ④ Outils (16 octobre 2026, Python 3.13)

| Outil | Résultat |
| --- | --- |
| `bandit -r src` et `bandit -r labs` | aucune alerte après correction |
| `pip-audit` | « No known vulnerabilities found » |
| `gitleaks detect` (tout l'historique) | « no leaks found » (1 faux positif justifié dans `.gitleaksignore`) |
| `pytest -m lab` | 26 tests verts |
