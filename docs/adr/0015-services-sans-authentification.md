# ADR 0015 — Correctif : Services qui ne s'authentifient pas

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : infrastructure · **Propriété DICP** : I·P

## Contexte
Un service qui accepte tout appel interne permet à un attaquant déjà présent sur le réseau de se faire passer pour un autre composant.

## Décision
Authentification mutuelle entre composants (mTLS ou jeton signé à durée courte) sur chaque flux interne de la matrice des flux.

## Conséquences
- Positive : chaque flux a une identité vérifiable et peut être révoqué.
- **Négative** : gestion de certificats ou de jetons à outiller, et risque de panne si un certificat expire sans être renouvelé.

## Preuve et non-régression
Dans le laboratoire : jeton HMAC-SHA256 à durée de 5 min, clé propre au service (`QUEENBEE_LAB_SERVICE_KEY`), liste d'appelants autorisés, horloge injectée, refus comptés. En production : mTLS sur les flux internes (F3, F4, matrice des flux). Tests : `::test_faille6_unauthenticated_calls_refused_and_counted` (sans jeton, forgé, expiré, appelant inconnu, modifié), `::test_faille6_valid_token_is_served`, `::test_faille6_refuses_to_start_without_service_key`.
