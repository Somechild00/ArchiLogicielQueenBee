# Modèle de menaces — Queen Bee (J1 · A1)

> Périmètre : détection d'intrusion sur journaux d'authentification. Un agent/serveur produit des
> journaux ; Queen Bee les lit, applique des règles, enregistre des incidents et alerte le SOC.
> Propriétés DICP : **D**isponibilité · **I**ntégrité · **C**onfidentialité · **P**reuve (traçabilité).

## 1. Actifs

| # | Actif | Pourquoi il compte | DICP |
|---|-------|--------------------|------|
| A1 | Journaux d'authentification (entrée) | Source unique de vérité de la détection ; s'ils sont faux, tout est faux. Contiennent noms d'utilisateurs et IP. | I, P, C |
| A2 | Base des incidents (SQLite) | Historique que le SOC consulte et peut produire en justice ; la perdre ou la falsifier aveugle l'équipe. | I, D, P |
| A3 | Clé secrète applicative (`.env`) | Sa fuite permet de se faire passer pour l'application ; un secret commité est un secret compromis. | C |
| A4 | Identifiants SMTP | Permettent d'envoyer de fausses alertes (ou d'en taire de vraies) au nom de Queen Bee. | C, I |
| A5 | Configuration des règles (seuils, types) | Un seuil à 100 000 ou un type de règle injecté désactive ou détourne la détection. | I, D |
| A6 | Canal d'alerte SOC (courriel) | Si l'alerte n'arrive pas, la détection ne sert à rien. | D, I |
| A7 | Capacité de calcul du service | Un journal piégé qui sature mémoire/CPU met Queen Bee hors service au pire moment. | D |

## 2. Acteurs

| Acteur | Légitime ? | Capacité / motivation |
|--------|-----------|-----------------------|
| Analyste SOC | Oui | Lit et qualifie les incidents (OPEN → TRIAGED → [CONTAINED] → CLOSED). |
| Administrateur / opérateur | Oui | Déploie, configure `.env`, lance Queen Bee. |
| Attaquant externe | Non | Fabrique des lignes de journal (nom d'utilisateur, IP) pour injecter ou noyer la détection. |
| Insider malveillant | Non | A un accès à la base ou au dépôt ; veut effacer ses traces ou voler un secret. |
| **Agent / serveur compromis** | Semble légitime | Source de journaux de confiance qui ment : fausses IP, journaux volumineux, horodatages falsifiés. |
| Serveur SMTP usurpé | Non | Se place en face pour intercepter les alertes et les identifiants. |

## 3. Diagramme de flux de données (DFD)

```mermaid
flowchart LR
    SRC["Serveurs / agents<br/>(journaux auth)"] -->|F1 lignes brutes| PARSE
    subgraph QB["Queen Bee (processus)"]
        PARSE["Parseur<br/>(valide, ignore le hostile)"] -->|F2 SecurityEvent valides| DET["Règles de détection"]
        DET -->|F3 Alert| SVC["DetectionService"]
        CFG["Config (Builder)"] -.->|F7 réglages| SVC
    end
    ENV[".env / environnement"] -->|F6 secrets| CFG
    SVC -->|F4 Incident| DB[("Base SQLite")]
    SVC -->|F5 alerte| SMTP["Serveur SMTP"]
    SMTP --> SOC["Analyste SOC"]
```

Frontières de confiance :

* **TB1 — Journaux → Queen Bee (F1).** Tout ce qui franchit TB1 est contrôlé par un attaquant
  potentiel : une ligne de journal contient du texte que l'attaquant a choisi (nom d'utilisateur,
  IP source). Justification : c'est exactement le chemin de l'injection SQL du script hérité.
* **TB2 — Queen Bee → base de données (F4).** Le stockage est un autre composant avec son propre
  langage (SQL) et ses propres droits ; une donnée mal transmise devient une instruction.
* **TB3 — Queen Bee ↔ extérieur de configuration et d'alerte (F5, F6).** Les secrets entrent
  par F6 (environnement/disque) et sortent par F5 (réseau vers SMTP) : deux points où un secret
  peut fuiter ou être intercepté.

## 4. STRIDE sur les flux qui traversent une frontière

| Flux | Lettre | Menace crédible | Réponse (exigence) |
|------|--------|-----------------|--------------------|
| F1 / TB1 | **S**poofing | Un agent compromis ou un attaquant forge des lignes avec l'IP d'une victime pour la faire bloquer / alerter. | Valider chaque champ à la frontière ; l'IP doit être une IP valide (EX-01). Limite : l'authenticité de la source relève de J2/J3 (signature des journaux). |
| F1 / TB1 | **T**ampering | Nom d'utilisateur `root'; DROP TABLE x;--` : injection dans la suite du traitement. | Allowlist de caractères et de longueur, actions hors liste refusées (EX-01). |
| F1 / TB1 | **D**enial of service | Ligne de plusieurs Mo, journal sans fin : mémoire saturée. | Longueur de ligne et nombre de lignes bornés (EX-05 pour les seuils ; tests du parseur). |
| F2→F3 / interne | **R**epudiation | Événement sans fuseau horaire : impossible de dire quand, donc de prouver. | Horodatage UTC avec fuseau obligatoire (EX-02). |
| F4 / TB2 | **T**ampering | Concaténer l'IP ou le message dans le SQL permet de modifier ou détruire la base. | Requêtes paramétrées uniquement (EX-08). |
| F4 / TB2 | **R**epudiation | Un incident passe de OPEN à CLOSED sans qualification : personne n'a rien vu. | Machine à états : pas de CLOSED sans TRIAGED (EX-06). |
| F4 / F2 | **T**ampering | Un événement modifié après validation contourne les contrôles. | Objets du domaine immuables (EX-03). |
| F6 / TB3 | **I**nformation disclosure | `print(settings)`, un log ou une trace affiche la clé ou le mot de passe SMTP. | Type `Secret` masqué partout ; aucun secret dans le dépôt (EX-07). |
| F5 / TB3 | **I**nformation disclosure | Identifiants SMTP ou contenu des alertes lus sur le réseau ; serveur usurpé (**S**). | STARTTLS avant le login ; secret révélé uniquement au moment du `login` (EX-07). |
| F6 / TB3 | **E**levation of privilege | Une config contenant `__import__('os')...` fait exécuter du code arbitraire si on instancie dynamiquement le nom de règle. | Fabrique à liste blanche, aucun `getattr`/`importlib` sur une chaîne externe (EX-04). |
| F6 / TB3 | **D**enial of service | Seuil `True` (= 1) : une alerte par événement, le SOC est noyé ; seuil énorme : plus aucune alerte. | Seuil entier, hors booléen, borné 1..100 000 (EX-05). |

Couverture : S, T, R, I, D, E toutes présentes au moins une fois.

## 5. Exigences de sécurité

Format : *quoi* **DOIT** *critère mesurable*. Chaque exigence pointe vers le test qui la prouve.

**EX-01** — Un `SecurityEvent` DOIT être refusé (`DomainError`) si l'IP n'est pas une adresse valide, si le nom d'utilisateur sort de `[A-Za-z0-9_.-]{1,64}`, ou si l'action n'est pas dans la liste autorisée.
Menace : T/S sur TB1 · Propriété : I
Preuve : `tests/test_domain.py::test_invalid_event_cannot_exist` (+ `tests/test_log_parser.py::test_parser_ignores_hostile_or_malformed_lines`)

**EX-02** — Un `SecurityEvent` DOIT être refusé si son horodatage n'a pas de fuseau horaire.
Menace : R sur le flux F2 · Propriété : P
Preuve : `tests/test_domain.py::test_naive_timestamp_rejected`

**EX-03** — Un `SecurityEvent` DOIT lever `FrozenInstanceError` à toute tentative de modification après construction.
Menace : T sur F2 · Propriété : I
Preuve : `tests/test_domain.py::test_event_is_immutable`

**EX-04** — La fabrique de règles DOIT lever `DomainError` pour tout nom de règle absent de la liste blanche, y compris `__import__('os')`, et pour toute clé de configuration inattendue.
Menace : E sur TB3 · Propriété : I
Preuve : `tests/test_domain.py::test_factory_rejects_unknown_rule` (+ `tests/test_abuse.py::test_abuse_malformed_rule_spec_is_rejected`)

**EX-05** — Un seuil de règle DOIT être un entier non booléen compris entre 1 et 100 000, à la création comme à la copie (Prototype).
Menace : D sur TB3 · Propriété : D
Preuve : `tests/test_domain.py::test_factory_rejects_bool_threshold`, `tests/test_creational.py::test_prototype_copy_is_revalidated`, `tests/test_abuse.py::test_abuse_invalid_threshold_is_rejected`

**EX-06** — Un incident DOIT passer par TRIAGED avant CLOSED ; toute autre transition DOIT lever `DomainError`.
Menace : R sur TB2 · Propriété : P
Preuve : `tests/test_domain.py::test_state_forbids_skipping_triage`

**EX-07** — Aucun secret (clé applicative, mot de passe SMTP) NE DOIT apparaître dans `repr`, `str` ou les messages d'erreur d'un objet de configuration ; les secrets DOIVENT provenir de l'environnement, jamais du code.
Menace : I sur TB3 · Propriété : C
Preuve : `tests/test_config.py::test_secret_never_appears_in_repr_or_str`, `tests/test_config.py::test_secret_is_read_from_environment_not_from_code`, `tests/test_abuse.py::test_abuse_builder_rejects_short_secret_without_leaking_it`

**EX-08** — Le dépôt SQLite DOIT stocker une donnée hostile (`x'); DROP TABLE incidents;--`) comme simple texte, sans modifier le schéma ni perdre d'autres lignes.
Menace : T sur TB2 · Propriété : I
Preuve : `tests/test_repositories.py::test_sql_injection_is_stored_as_data_not_executed`

## 6. Limites connues (honnêteté du modèle)

* L'authenticité de la **source** des journaux (menace S sur F1 par un agent compromis) n'est
  qu'atténuée par la validation de forme : la signature des journaux est à traiter aux jours 2 et 3.
* La base SQLite n'est pas chiffrée ni protégée contre un insider qui a accès au fichier (menace T/I
  sur A2 hors du processus) : exigence à ouvrir au J2.
