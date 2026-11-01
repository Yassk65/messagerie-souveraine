# Messagerie souveraine de l'administration

Hackathon 226 – Édition 2026 · Sprint technique pré-hackathon · Équipe : _à compléter_ · Université : _à compléter_

## Concept
Messagerie instantanée (messages, groupes, fichiers) pour les agents publics, **hébergeable sur l'infrastructure de l'État**, chiffrée de bout en bout, fermée (aucune inscription libre, aucune fédération) et sans service tiers.

## Architecture
```
Agents (Element Web / mobile) ──HTTP──> Synapse (serveur Matrix) ──> PostgreSQL
                                          └─ ne stocke que du contenu chiffré (m.room.encrypted)
```
- **Chiffrement** : protocole Matrix, Olm (1:1) et Megolm (groupes), chiffrement activé par défaut pour tous les salons. Aucune cryptographie développée par l'équipe.
- **Identité** : inscriptions fermées ; comptes créés uniquement par un administrateur ; politique de mot de passe ; 2e facteur et rôles : _voir « État d'avancement »_.
- **Révocation** : `scripts/revoke.sh` désactive le compte, ferme toutes les sessions et retire l'agent de tous les salons.
- **Métadonnées** : présence désactivée, adresses IP conservées 1 jour, pas d'aperçu de liens, notifications sans contenu, pas de fédération. Le serveur voit encore : qui est membre de quel salon, quand un message est envoyé, la taille des fichiers, les noms/sujets de salons (voir la note de sécurité).

## Technologies et licences
| Composant | Rôle | Licence | Projet |
|---|---|---|---|
| Synapse | Serveur Matrix | AGPL-3.0 | https://github.com/element-hq/synapse |
| Element Web | Client | AGPL-3.0 / GPL-3.0 | https://github.com/element-hq/element-web |
| PostgreSQL | Base de données | PostgreSQL License | https://www.postgresql.org |
| Code de ce dépôt | Configuration, scripts, extensions | AGPL-3.0 (fichier `LICENSE`) | ce dépôt |

**Niveau d'engagement open source : Étendre et adapter** (à partir de Synapse et d'Element).

## Installation (une seule commande)
Prérequis : Docker et Docker Compose.
```bash
docker compose up -d
./scripts/demo_accounts.sh      # crée des comptes FICTIFS
```
Client : http://localhost:8080 · Serveur : http://localhost:8008
Pour un autre nom de domaine : copier `.env.example` en `.env` et adapter `SERVER_NAME` et `PUBLIC_BASEURL`.

**Comptes de démonstration (fictifs)** : `admin`, `aminata.ouedraogo`, `ibrahim.sawadogo`, `fatoumata.kabore` — mot de passe : `Demo-Fictif-2026!`

## Vérifications pour le jury
```bash
./scripts/check_server_blind.sh                 # aucun message en clair en base
ADMIN_PASSWORD='Demo-Fictif-2026!' ./scripts/revoke.sh aminata.ouedraogo   # révocation
```

## État d'avancement
- [x] Déploiement en une commande, inscriptions fermées, E2EE par défaut, pas de fédération
- [x] Révocation, vérification « serveur aveugle »
- [ ] Second facteur d'authentification et gestion des rôles
- [ ] Fonctionnalité d'innovation : _à compléter_
- [ ] Interface en langue nationale, tests automatisés (bonus)

## Limites connues
- Le serveur voit les métadonnées listées ci-dessus.
- Un agent révoqué conserve les messages déjà reçus sur son appareil (d'où l'effacement à distance, piste d'amélioration).
- Les ports sont exposés en HTTP pour la démonstration : en production, placer un proxy HTTPS devant et bloquer `/_synapse/admin` depuis l'extérieur.
- Les images Docker doivent être épinglées sur une version précise.
