# ADR 0016 — Correctif : Comparaison de jeton non constante

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : sécurité · **Propriété DICP** : C

## Contexte
Comparer deux jetons avec `==` s'arrête au premier caractère différent : le temps de réponse révèle le jeton petit à petit.

## Décision
Utiliser `hmac.compare_digest` sur des octets de même type, et ne jamais journaliser le jeton.

## Conséquences
- Positive : le temps de comparaison ne dépend plus du contenu.
- **Négative** : la protection ne vaut que si tout le chemin est en temps constant (pas de recherche en base avant la comparaison).

## Preuve et non-régression
`check_token` utilise `hmac.compare_digest` sur des octets. Tests : `::test_faille7_token_comparison_is_constant_time` (espion sur `compare_digest`), `::test_faille7_non_string_or_non_ascii_token_refused_without_crash`.
