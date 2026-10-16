# Traçabilité exigence ↔ menace ↔ test

Chaque exigence ou menace traitée pointe vers au moins un test qui la prouve. Détail : `docs/threat_model.md`.

| Exigence / menace | STRIDE | DICP | Test(s) |
| --- | --- | --- | --- |
| EX-01 Événement invalide refusé | T, S | I | `test_domain.py::test_invalid_event_cannot_exist`, `test_log_parser.py::test_parser_rejects_hostile_or_malformed_lines` |
| EX-02 Horodatage avec fuseau | R | P | `test_domain.py::test_naive_timestamp_rejected` |
| EX-03 Événement immuable | T | I | `test_domain.py::test_event_is_immutable` |
| EX-04 Fabrique à liste blanche | E | I | `test_domain.py::test_factory_rejects_unknown_rule`, `test_abuse.py::test_abuse_malformed_rule_spec_is_rejected` |
| EX-05 Seuil borné, non booléen | D | D | `test_domain.py::test_factory_rejects_bool_threshold`, `test_creational.py::test_prototype_copy_is_revalidated` |
| EX-06 Pas de CLOSED sans TRIAGED | R | P | `test_domain.py::test_state_forbids_skipping_triage` |
| EX-07 Secret jamais affiché, lu dans l'environnement | I | C | `test_config.py::test_secret_never_appears_in_repr_or_str`, `test_config.py::test_key_is_read_from_environment_not_from_code` |
| EX-08 Injection SQL stockée comme texte | T | I | `test_repositories.py::test_sql_injection_is_stored_as_data_not_executed` |
| M-J2-01 Signature forgée | S | I | `test_adapters.py::test_abuse_forged_signature_rejected` |
| M-J2-02 Champ modifié après signature | T | I | `test_inbound_malicious.py::test_tampered_field_after_signing_rejected` |
| M-J2-03 Champ en trop | T | I | `test_adapters.py::test_abuse_extra_field_rejected` |
| M-J2-04 Message énorme | D | D | `test_inbound_malicious.py::test_oversized_message_rejected_before_signature_check` |
| M-J2-05 Ligne de journal piégée | T, D | I, D | `test_adapters.py::test_malicious_lines_rejected`, `test_adapters.py::test_parser_is_fast_on_adversarial_input` |
| M-J2-06 Inondation d'alertes | D | D | `test_services.py::test_abuse_rate_limiter_absorbs_alert_flood` |
| M-J2-07 Lecteur qui modifie | E | I | `test_hexagon.py::test_reader_cannot_modify_through_proxy` |
| M-J2-08 Lecture sans rôle | I | C | `test_services.py::test_proxy_blocks_principal_without_role` |
| M-J2-09 Injection SQL (sqlite) | T | I | `test_services.py::test_sqlite_repo_resists_injection` |
| M-J2-10 Commande pare-feu piégée | T | I | `test_services.py::test_command_undo` |
| M-J2-11 Abonné en panne | D | D | `test_hexagon.py::test_observer_failure_does_not_block_other_subscribers` |
| M-J2-12 Alerte sans trace | R | P | `test_services.py::test_audit_decorator_logs` |
| M-J2-13 Flux de menaces externe | T | I | `test_inbound_malicious.py::test_threat_feed_rejects_unknown_risk_level` |
| M-J3-01 Secret en dur | I | C | `test_lab_vulnerable.py::test_faille1_no_secret_in_code_and_refuses_to_start_without_key` |
| M-J3-02 ReDoS | D | D | `test_lab_vulnerable.py::test_faille2_redos_is_gone` |
| M-J3-03 Désérialisation pickle | T, E | I | `test_lab_vulnerable.py::test_faille3_pickle_payload_is_refused_without_running_code` |
| M-J3-04 SQL par f-string | T | I | `test_lab_vulnerable.py::test_faille4_sql_injection_no_longer_dumps_table` |
| M-J3-05 Aucune autorisation | E | C, I | `test_lab_vulnerable.py::test_faille5_without_analyst_role_cannot_close` |
| M-J3-06 Services non authentifiés | S | I, P | `test_lab_vulnerable.py::test_faille6_unauthenticated_calls_refused_and_counted` |
| M-J3-07 Comparaison non constante | I | C | `test_lab_vulnerable.py::test_faille7_token_comparison_is_constant_time` |
| Contrat d'architecture | — | I | `lint-imports` : 1 contrat respecté, 0 cassé |
