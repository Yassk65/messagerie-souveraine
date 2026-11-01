# Messagerie Souveraine de l'Administration — « FasoSouverain »

Hackathon 226 – Édition 2026 (MTDPCE / DGTD) · Sprint technique pré-hackathon  
**Équipe** : _FasoSouverain (à compléter avec vos noms)_ · **Université** : _Université du Burkina Faso (à compléter)_

---

## 1. Concept
Messagerie instantanée souveraine (messages, groupes ministériels, notes vocales et fichiers) destinée aux agents publics du Burkina Faso, **hébergeable sur l'infrastructure de l'État en une seule commande**, chiffrée de bout en bout (E2EE), strictement fermée aux intrus (aucune inscription publique, aucune fédération externe) et fonctionnant **sans aucun service tiers**.

---

## 2. Architecture et Socle de Sécurité
```
Agents Publics (Portail Web Souverain :3000 / Element Web :8080)
   │  Chiffrement E2EE local (Matrix Olm/Megolm + WebCrypto AES-256-GCM)
   │  Authentification Forte : Mot de passe (12+ car.) + 2e Facteur TOTP (RFC 6238)
   ▼
Portail Souverain & Serveur Matrix Synapse (:8008) ──> PostgreSQL 16
   └─ Ne stocke que des évènements chiffrés (m.room.encrypted) — 0 message en clair
```

- **Chiffrement de bout en bout (E2EE)** : Protocole **Matrix (Olm en 1:1 / Megolm en groupe)** et API standard **WebCrypto (`AES-256-GCM`)**. Chiffrement forcé par défaut pour tous les salons (`encryption_enabled_by_default_for_room_type: all`) et rejet strict de tout évènement en clair (`m.room.message`). Aucune cryptographie maison.
- **Identité vérifiée, 2FA & Rôles (RBAC)** : Inscriptions publiques fermées (`enable_registration: false`). Enrôlement exclusif par l'administrateur (`ADMIN_SG`). Authentification forte à **2 facteurs (Mot de passe + Code TOTP à 6 chiffres RFC 6238)** et gestion de 3 rôles :
  - `ADMIN_SG` (Administrateur Sécurité DGTD/SG) : enrôlement, révocation immédiate, gestion des canaux officiels.
  - `DIRECTEUR` (Directeur / Chef de service) : émission d'Instructions de Service et de messages `CONFIDENTIEL`.
  - `AGENT_PUBLIC` (Agent assermenté) : échanges en niveau `NORMAL` et `DIFFUSION_RESTREINTE`, accusés de réception.
- **Révocation immédiate** : Via l'interface d'administration en 1 clic ou via `./scripts/revoke.sh`, le compte d'un agent est immédiatement désactivé, ses jetons d'accès sont détruits (`HTTP 401` instantané), il est retiré de tous les salons et la clé de groupe Megolm est renouvelée.
- **Minimisation des métadonnées** : Présence en ligne désactivée (`presence: false`), adresses IP purgées après 24h (`user_ips_max_age: 1d`), pas d'aperçu d'URL (`url_preview_enabled: false`), notifications sans contenu, fédération coupée. Le serveur voit uniquement qui est membre d'un salon et l'horodatage de transit des paquets chiffrés (voir [docs/NOTE_SECURITE.md](docs/NOTE_SECURITE.md)).

---

## 3. Fonctionnalités Innovantes pour l'Administration Burkinabè
1. **Niveaux de Classification des Messages (`NORMAL`, `DIFFUSION_RESTREINTE`, `CONFIDENTIEL`)** : Blocage de la copie/transfert sur les messages classifiés, bandeau anti-capture et **expiration automatique (TTL)** (ex: 30s, 5 min, 1h).
2. **Instructions de Service avec Accusé de Lecture à Valeur Probante** : Les Directeurs peuvent émettre une instruction officielle exigeant un accusé de lecture horodaté et signé cryptographiquement (**HMAC-SHA256**) par chaque agent avec son matricule.
3. **Annuaire Officiel par Ministère et Fonction** : Répertoire filtrable par ministère (`MTDPCE`, `MEFP`, `MATDS`, `MS`, `SGG-CM`), direction, titre et statut d'habilitation temps-réel.
4. **Interface et Notes Vocales en Langues Nationales (Bonus +3 pts)** : Bascule instantanée de l'interface en **Français, Mooré, Dioula (Julakan) et Fulfuldé**, avec envoi de notes vocales chiffrées de bout en bout.
5. **Bouton d'Urgence (Panic Wipe)** : En cas de perte ou de menace sur le terrain, efface immédiatement les clés cryptographiques en mémoire/stockage local et révoque toutes les sessions de l'agent.

---

## 4. Technologies Utilisées et Licences Open Source
| Composant | Rôle | Licence OSI | Lien du projet |
|---|---|---|---|
| **Synapse** (`v1.118.0`) | Serveur Matrix E2EE | AGPL-3.0 | https://github.com/element-hq/synapse |
| **Element Web** (`v1.11.86`) | Client Matrix de référence | AGPL-3.0 / GPL-3.0 | https://github.com/element-hq/element-web |
| **PostgreSQL** (`16-alpine`) | Base de données | PostgreSQL License | https://www.postgresql.org |
| **Node.js** (`22-alpine`) | Portail Souverain (2FA, RBAC, Innovations) & Tests | MIT License | https://nodejs.org |
| **FasoSouverain** (ce dépôt) | Portail, configuration, scripts et documentation | **AGPL-3.0** (`LICENSE`) | Ce dépôt |

**Niveau d'engagement open source : Étendre et adapter** (à partir de Synapse et d'Element).

---

## 5. Installation et Démarrage Rapide

### Option A — Déploiement complet en UNE commande (Docker Compose)
```bash
docker compose up -d --build
./scripts/demo_accounts.sh      # crée les comptes fictifs dans Synapse
```
- **Portail & Messagerie Souveraine (2FA, Rôles, Innovations, Langues nationales)** : http://localhost:3000
- **Client Element Web** : http://localhost:8080 · **Serveur Synapse** : http://localhost:8008

### Option B — Démarrage direct du Portail Souverain & Suite de Tests (sans Docker requis)
```bash
node portal/src/server.js       # lance le portail sur http://localhost:3000
node --test tests/security.test.js   # exécute les 6 tests automatisés de sécurité (Bonus +2 pts)
```

---

## 6. Comptes de Démonstration (100 % Fictifs) et Vérifications pour le Jury
Mot de passe de démonstration : `Demo-Fictif-2026!` (le code **2FA TOTP à 6 chiffres** temps-réel est affiché sur la console d'aide du portail pour faciliter les tests du jury) :
- `admin` (`ADMIN_SG` — Commandant Ousmane Traoré, MTDPCE/DGTD)
- `aminata.ouedraogo` (`DIRECTEUR` — Directrice des Infrastructures, MTDPCE)
- `ibrahim.sawadogo` (`AGENT_PUBLIC` — Inspecteur du Trésor, MEFP)
- `fatoumata.kabore` (`AGENT_PUBLIC` — Chargée des Opérations, MATDS)

**Commandes de vérification en direct pour l'entretien du jury :**
```bash
node --test tests/security.test.js              # vérifie 2FA, anti-intrus, serveur aveugle, RBAC et révocation
./scripts/check_server_blind.sh                 # vérifie qu'il y a 0 message en clair dans PostgreSQL
ADMIN_PASSWORD='Demo-Fictif-2026!' ./scripts/revoke.sh fatoumata.kabore   # révocation immédiate en CLI
```

---

## 7. Limites Connues et Documents du Dossier
- Le serveur ne lit aucun message mais voit les métadonnées de routage minimales (membres d'un salon, horodatage).
- En production, placer un reverse-proxy HTTPS (TLS 1.3) devant les services et restreindre `/_synapse/admin` au réseau d'administration.
- Documents complets dans `docs/` : [Note de Pré-Projet (2 pages)](docs/NOTE_PRE_PROJET.md) et [Note de Sécurité (2 pages)](docs/NOTE_SECURITE.md).
