# ADR 0005 — Sauvegarde 3-2-1 immuable, RPO 15 min et RTO 1 h

- **Statut** : accepté
- **Date** : 16 octobre 2026
- **Décideurs** : Khady, Amale

## Contexte
Une perte de base ou un rançongiciel ne doit pas faire perdre les incidents ouverts.

## Décision
Sauvegarde complète nocturne, archivage continu, copie hors site immuable, test de reprise trimestriel.

## Conséquences
- Positive : reprise chiffrée et testée, résistante à l'effacement.
- **Négative** : coût de stockage et de test ; RPO de 15 min : jusqu'à 15 min d'événements peuvent être perdus.
