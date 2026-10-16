# ADR 0013 — Correctif : Requête SQL construite par f-string

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : persistance · **Propriété DICP** : I

## Contexte
Une valeur concaténée dans la requête permet d'en changer le sens (injection SQL).

## Décision
Requêtes paramétrées (`?`) dans l'adaptateur de persistance, uniquement ; le domaine valide aussi ses entrées.

## Conséquences
- Positive : les données ne peuvent plus être interprétées comme du SQL.
- **Négative** : les noms de tables ou de colonnes ne se paramètrent pas : ils doivent venir d'une liste blanche écrite dans le code.

## Preuve et non-régression
`find_incidents` utilise `?`. Test : `::test_faille4_sql_injection_no_longer_dumps_table` (injection sans effet, table intacte).
