# ADR 0001 — Architecture hexagonale (ports et adaptateurs) pour Queen Bee

- **Statut** : accepté
- **Date** : 15 octobre 2026
- **Décideurs** : _(noms du groupe)_

## Contexte

Queen Bee ingère des événements de sécurité venus d'agents et de journaux (entrées **non fiables**),
applique des règles de détection, crée des incidents et notifie un SOC. Contraintes :
équipe de 3 à 4 personnes, délai de 3 jours, volume modeste (milliers d'événements par minute au plus),
mais exigence forte de **testabilité** et de **frontières de confiance explicites**.

## Options considérées

| Critère | A. Architecture en couches classique | B. Architecture hexagonale |
| --- | --- | --- |
| Maintenabilité | Simple au départ ; la logique tend à s'étaler dans les services et la base | Règles métier isolées au centre ; changer de base ou de canal = changer un adaptateur |
| Frontières réseau | Implicites : la validation se retrouve là où chaque développeur la met | Explicites : toute entrée passe par un adaptateur d'entrée (taille, signature, schéma) |
| Secrets | Souvent lus un peu partout (`os.environ` dans le métier) | Lus uniquement dans la racine de composition, injectés aux adaptateurs |
| Failles typiques | SQL concaténé dans la logique, contrôle d'accès oublié sur un chemin | Adaptateur mal écrit (mais testable isolément) ; contrôle d'accès centralisé dans les cas d'usage |
| Testabilité | Tests souvent lents, base réelle nécessaire | Doublures en mémoire, suite < 1 s |

## Décision

Nous adoptons l'**architecture hexagonale** : `domain` (règles) ← `application` (cas d'usage et ports,
déclarés en `Protocol`) ← `adapters` (entrée : message signé, ligne de journal ; sortie : dépôt mémoire/sqlite,
notificateurs, pare-feu). Le sens des dépendances est vérifié automatiquement par **import-linter**
(contrat de couches, `make check`).

**Proportionnalité** : le projet reste petit, nous n'ajoutons ni bus d'événements, ni microservices,
ni CQRS. Un seul processus, un seul dépôt.

## Conséquences

**Positives**
- Le domaine et les cas d'usage se testent sans base ni réseau (suite complète en dessous de 2 s).
- Les points d'entrée hostiles sont concentrés dans peu de fichiers : surface d'audit réduite.
- Le contrôle d'accès (autoriser → vérifier → règle → persister) est écrit une fois, dans l'application.

**Négatives (assumées)**
- **Plus de fichiers et d'indirections** (ports, adaptateurs, racine de composition) pour un projet de cette taille : coût d'entrée pour un nouveau développeur.
- **Duplication de modèle** : le dépôt sqlite doit retraduire `Incident` en lignes et inversement ; une évolution du domaine demande de toucher l'adaptateur.
- **Risque de fausse sécurité** : l'architecture ne valide rien toute seule. Un adaptateur d'entrée mal écrit reste une faille ; seuls les tests malveillants et la revue la détectent.
- **Le contrat import-linter ne voit pas tout** : il interdit les inversions de couches, pas l'usage de bibliothèques techniques dans le centre (à surveiller en revue).
- **Rate limiter en mémoire** : l'état est perdu au redémarrage et n'est pas partagé entre processus ; acceptable maintenant, à revoir si nous passons à plusieurs instances.

## Suivi

Revoir cette décision si : plusieurs instances sont déployées, ou si le volume impose un traitement asynchrone.
