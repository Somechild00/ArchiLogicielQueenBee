# ADR 0014 — Correctif : Aucune autorisation dans le service

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : application · **Propriété DICP** : C·I

## Contexte
N'importe quel appelant pouvait modifier un incident : le service ne vérifiait aucun rôle.

## Décision
Vérifier le rôle **en premier** dans le cas d'usage (`require_role`), avant d'accéder au dépôt, et compter les refus.

## Conséquences
- Positive : le contrôle est écrit une seule fois, au centre, pour tous les adaptateurs d'entrée.
- **Négative** : chaque nouveau cas d'usage doit penser à appeler le contrôle ; aucun mécanisme ne l'impose automatiquement.

## Preuve et non-régression
`close_incident(principal, id)` appelle `require_role` (rôle `analyst`) avant toute lecture ou écriture ; refus comptés (`denied`). Tests : `::test_faille5_without_analyst_role_cannot_close` (aucun effet de bord), `::test_faille5_analyst_can_close`.
