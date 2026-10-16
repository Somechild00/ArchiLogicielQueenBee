# ADR 0002 — Segmentation en zones avec refus par défaut

- **Statut** : accepté
- **Date** : 16 octobre 2026
- **Décideurs** : Khady, Amale

## Contexte
Les agents et les postes sont hostiles ; la base et les journaux sont critiques.

## Décision
Six zones (Z0 à Z5), flux déclarés un par un dans `docs/infra/flux.md`, règle finale « tout le reste est refusé ».

## Conséquences
- Positive : un attaquant qui compromet la passerelle n'atteint ni la base ni les journaux.
- **Négative** : plus de règles de pare-feu à maintenir et à tester ; un flux oublié bloque l'application.
