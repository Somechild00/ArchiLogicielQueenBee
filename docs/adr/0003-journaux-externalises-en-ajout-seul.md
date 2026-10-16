# ADR 0003 — Journaux externalisés en ajout seul

- **Statut** : accepté
- **Date** : 16 octobre 2026
- **Décideurs** : Khady, Amale

## Contexte
Un attaquant qui prend la main sur l'application voudra effacer ses traces (menace R).

## Décision
Journaux envoyés vers la zone Z4 avec un droit d'écriture seule ; l'application ne peut ni lire ni supprimer.

## Conséquences
- Positive : les preuves survivent à la compromission de l'application.
- **Négative** : coût d'exploitation (collecteur à superviser) et perte des journaux si le collecteur est indisponible, d'où un tampon local temporaire.
