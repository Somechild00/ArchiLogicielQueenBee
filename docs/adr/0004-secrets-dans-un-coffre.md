# ADR 0004 — Secrets dans un coffre, rotation de 90 jours

- **Statut** : accepté
- **Date** : 16 octobre 2026
- **Décideurs** : Khady, Amale

## Contexte
Une clé unique et partagée est un point de compromission unique ; un secret commité est perdu.

## Décision
Secrets lus dans un coffre au démarrage, une clé par agent, rotation de 90 jours, `gitleaks` avant rendu.

## Conséquences
- Positive : une clé volée ne compromet qu'un agent et elle expire.
- **Négative** : dépendance au coffre au démarrage (si le coffre est indisponible, l'application ne démarre pas) et procédure de rotation à outiller.
