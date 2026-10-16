# ADR 0012 — Correctif : Désérialisation pickle

- **Statut** : accepté (preuve écrite, correctif appliqué, test inversé vert)
- **Date** : 16 octobre 2026 · **Décideurs** : Khady, Amale
- **Couche d'origine** : adaptateur · **Propriété DICP** : I

## Contexte
`pickle.loads` exécute du code arbitraire contenu dans les données reçues.

## Décision
Remplacer pickle par JSON, avec schéma strict, taille bornée et signature vérifiée avant toute lecture.

## Conséquences
- Positive : plus aucune exécution de code possible depuis une entrée.
- **Négative** : JSON ne transporte que des types simples ; les objets complexes demandent une conversion explicite à écrire.

## Preuve et non-régression
`receive_agent_message` : JSON, 4 Kio maximum, ensemble de clés exact, valeurs texte. La signature est vérifiée dans le vrai adaptateur (`src/queenbee/adapters/inbound/agent_api.py`). Tests : `::test_faille3_pickle_payload_is_refused_without_running_code`, `::test_faille3_bad_messages_rejected`, `::test_faille3_valid_json_message_accepted`.
