# Secrets, journalisation, sauvegarde et reprise

## Secrets et identités

| Secret | Où il vit | Qui y accède | Comment on le change |
| --- | --- | --- | --- |
| Clé de signature des agents (`QUEENBEE_AGENT_KEY`) | coffre (prod), `.env` ignoré par Git (dev) | l'application au démarrage ; chaque agent possède sa propre clé | rotation tous les 90 jours ou dès suspicion ; la nouvelle clé est acceptée en parallèle de l'ancienne pendant une période de transition |
| Mot de passe du compte applicatif de la base | coffre | l'application uniquement | rotation tous les 90 jours, sans redéploiement du code |
| Certificats TLS et mTLS | coffre / autorité interne | passerelle, application, base | durée de vie courte (≤ 90 jours), renouvellement automatisé |
| Jeton de l'API pare-feu | coffre | l'application | rotation tous les 90 jours, droits limités au blocage d'IP |
| Accès d'administration | clé personnelle + MFA | administrateurs nominatifs | révocation immédiate au départ d'une personne |

Règles : aucun secret dans le dépôt ni dans une image, un journal ou un message d'erreur ; `gitleaks` avant chaque rendu ;
un secret commité est considéré comme compromis et régénéré.

## Journalisation

| On journalise | On ne journalise **jamais** |
| --- | --- |
| authentifications réussies et échouées | secrets, clés, jetons, signatures |
| refus d'accès (rôle manquant) et compteurs de rejets | messages bruts reçus (risque d'injection de lignes et de fuite) |
| création d'incident, changement de statut, avec l'identité de l'auteur | mots de passe, même hachés |
| alertes déclenchées (règle, IP, gravité) | contenu libre d'un utilisateur non nettoyé |
| blocages d'IP et annulations | données personnelles au-delà de l'identifiant et de l'IP nécessaires |
| actions d'administration via le bastion | |

Les journaux partent vers le collecteur de la zone Z4 (flux F5 à F7). **L'application ne peut pas effacer ses journaux** :
elle dispose d'un droit d'écriture seule, le stockage est en ajout seul (append-only), les horloges sont synchronisées (NTP),
la conservation est de 12 mois.

## Sauvegarde et reprise

| Indicateur | Valeur | Justification |
| --- | --- | --- |
| **RPO** (perte de données acceptable) | **15 minutes** | un incident ouvert perdu est un incident non traité ; archivage continu des journaux de transaction |
| **RTO** (délai de remise en service) | **1 heure** | l'outil est important mais pas vital ; il existe une procédure manuelle de repli |
| Fréquence | sauvegarde complète chaque nuit + archivage continu | complète les 15 minutes de RPO |
| Copies | 3 copies, 2 supports, 1 hors site et **immuable** | une attaque par rançongiciel ne peut pas les effacer |
| Chiffrement | oui, clé stockée dans le coffre | confidentialité des sauvegardes |

**Scénario de test de reprise (à jouer chaque trimestre)**
1. Simuler la perte de la base : arrêter le serveur et détruire son volume dans l'environnement de test.
2. Restaurer la dernière sauvegarde complète sur un hôte vierge, puis rejouer les journaux de transaction.
3. Pointer l'application sur la base restaurée et relancer les tests de fumée (`pytest`, lecture des incidents ouverts).
4. Mesurer : durée totale (doit rester sous 1 h) et date de la dernière donnée retrouvée (au plus 15 min avant la panne).
5. Consigner le résultat et les écarts dans la trace de release.
