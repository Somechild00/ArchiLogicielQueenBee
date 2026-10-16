# ADR 0011 — Correctif : Regex à retour arrière exponentiel (ReDoS)

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : adaptateur · **Propriété DICP** : D

## Contexte
Une expression régulière avec des quantificateurs imbriqués peut occuper le processeur pendant des minutes sur une ligne bien choisie.

## Décision
Borner la longueur avant d'appliquer la regex et la réécrire sans imbrication (classes de caractères simples, `fullmatch`) ; le temps devient linéaire.

## Conséquences
- Positive : une ligne hostile ne peut plus bloquer le traitement.
- **Négative** : la regex stricte rejette quelques lignes autrefois acceptées ; il faut accepter ces faux rejets, qui sont comptés.

## Preuve et non-régression
Longueur bornée à 64 puis `fullmatch` sur `[A-Za-z0-9_.\-]{1,64}`. Tests : `::test_faille2_redos_is_gone` (50 000 caractères rejetés en moins de 0,1 s), `::test_faille2_legit_usernames_still_accepted`.
