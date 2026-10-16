# Modèle de menaces — ajouts du jour 2
_À recopier/fusionner dans `docs/threat_model.md`._

| ID | Nouveau flux | Menace (STRIDE) | Parade | Test |
| --- | --- | --- | --- | --- |
| M-J2-01 | Agent → SignedEventReader | S : signature forgée | HMAC-SHA256 + `compare_digest` | `test_forged_signature_rejected` |
| M-J2-02 | Agent → SignedEventReader | T : champ modifié après signature | signature sur le contenu canonique | `test_tampered_field_after_signing_rejected` |
| M-J2-03 | Agent → SignedEventReader | T : champ en trop (mass assignment) | schéma strict, ensemble de clés exact | `test_extra_field_rejected_even_if_signed` |
| M-J2-04 | Entrée → lecteur / adaptateur | D : message ou ligne énorme | borne de taille avant tout parsing | `test_oversized_message_rejected_before_parsing` |
| M-J2-05 | Journal → LogLineAdapter | T : ligne piégée, injection de ligne | regex stricte en `fullmatch`, longueur bornée | `test_trapped_log_line_rejected_and_counted` |
| M-J2-06 | Application → notificateurs | D : inondation d'alertes | fenêtre limitée, rejets comptés | `test_abuse_rate_limiter_absorbs_alert_flood` |
| M-J2-07 | Utilisateur → IncidentService | E : lecteur qui modifie | rôle exigé avant tout accès au dépôt | `test_reader_cannot_modify_through_proxy` |
| M-J2-08 | Application → sqlite | T : injection SQL | requêtes paramétrées | `test_sqlite_repo_resists_injection` |
| M-J2-09 | Application → pare-feu | T : commande piégée | validation d'IP avant exécution | `test_command_undo` |
| M-J2-10 | Notificateur en panne | D : un abonné bloque les autres | FanOutNotifier isole et compte les pannes | `test_observer_failure_does_not_block_other_subscribers` |

**Risque résiduel** : rejeu d'un message signé valide (pas de nonce ni d'horodatage borné) ;
à traiter en J3 ou à documenter comme risque accepté.
