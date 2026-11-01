# Note de Pré-Projet — « FasoSouverain » : La Messagerie Souveraine de l'Administration
**Hackathon 226 – Édition 2026 (MTDPCE / DGTD) · Sprint Technique Pré-Hackathon**

---

## 1. Concept et Vision Souveraine
Les agents publics du Burkina Faso échangent quotidiennement des instructions de service, notes ministérielles et rapports opérationnels. L'utilisation de messageries grand public (WhatsApp, Telegram) expose l'État à des risques majeurs de fuite de métadonnées, de dépendance juridique et de coupure de service.

**FasoSouverain** est une plateforme de messagerie instantanée souveraine, chiffrée de bout en bout, hébergeable intégralement sur les serveurs de l'État (ANPTIC / Data Center national) sans aucun service tiers. Elle combine la robustesse industrielle de l'écosystème **Matrix (Synapse + Element)** avec un **Portail Souverain Burkinabè** répondant aux besoins concrets des ministères : authentification forte à 2 facteurs (TOTP), annuaire par ministère, classification des messages (`Diffusion Restreinte`, `Confidentiel État`), accusés de lecture à valeur probante et interface en langues nationales (**Français, Mooré, Dioula, Fulfuldé**).

---

## 2. Architecture Technique et Protocole de Chiffrement

```
┌───────────────────────────────────────────────────────────────────────────────────┐
│ POSTE / MOBILE DE L'AGENT PUBLIC (Chiffrement / Déchiffrement local E2EE)         │
│  ├─ Client Souverain Web (Mooré / Dioula / Fulfuldé / FR) + Element Web (:8080)   │
│  └─ Protocole Matrix Olm / Megolm + WebCrypto AES-256-GCM (Clés sur l'appareil)   │
└───────────────────────────────┬───────────────────────────────────────────────────┘
                                │ HTTPS / REST (Payloads chiffrés m.room.encrypted)
                                ▼
┌───────────────────────────────────────────────────────────────────────────────────┐
│ INFRASTRUCTURE SOUVERAINE DE L'ÉTAT (Docker Compose — Zéro appel externe)         │
│  ├─ Portail & Passerelle Souveraine (:3000) : 2FA TOTP (RFC 6238), RBAC,          │
│  │  Annuaire Ministériel, Accusés signés HMAC-SHA256, Révocation & Panic Wipe     │
│  ├─ Serveur Matrix Synapse (:8008) : Routage E2EE, Fédération coupée, Anti-Intrus │
│  └─ Base PostgreSQL 16 : Stockage exclusif d'évènements chiffrés (0 texte clair)  │
└───────────────────────────────────────────────────────────────────────────────────┘
```

### Protocole de chiffrement retenu (Aucune cryptographie maison)
- **Protocole Matrix (Olm / Megolm)** combiné à l'implémentation standard **WebCrypto (`AES-256-GCM` / `PBKDF2-SHA256`)** et **Node.js `crypto` (OpenSSL)** :
  - **Olm (Double Ratchet Curve25519 / AES-256)** : assure l'établissement des canaux 1-à-1 entre appareils d'agents.
  - **Megolm (`m.megolm.v1.aes-sha2`)** : assure le chiffrement de bout en bout des salons de groupe ministériels.
  - **Forçage serveur** : `encryption_enabled_by_default_for_room_type: all` dans Synapse et rejet strict de tout évènement en clair `m.room.message`. Le serveur ne détient jamais les clés de déchiffrement.

---

## 3. Composants Open Source, Licences et Niveau d'Engagement

| Composant | Rôle dans l'architecture | Licence OSI | Lien vers le projet officiel |
|---|---|---|---|
| **Matrix Synapse** (`v1.118.0`) | Serveur de messagerie Matrix (routage E2EE) | AGPL-3.0 | https://github.com/element-hq/synapse |
| **Element Web** (`v1.11.86`) | Client Matrix standard de référence | AGPL-3.0 / GPL-3.0 | https://github.com/element-hq/element-web |
| **PostgreSQL** (`16-alpine`) | Base de données relationnelle souveraine | PostgreSQL License | https://www.postgresql.org |
| **Node.js** (`22-alpine`) | Exécution du Portail Souverain & Tests | MIT License | https://nodejs.org |
| **Portail FasoSouverain** (ce dépôt) | 2FA TOTP, RBAC, Innovations métier, Scripts | **AGPL-3.0** (`LICENSE`) | Dépôt public de l'équipe |

**Niveau d'engagement Open Source déclaré : « Étendre et adapter »**
Nous étendons le couple éprouvé **Synapse / Element** par une couche métier souveraine (`portal/`) sans aucune dépendance externe payante ou propriétaire, publiée intégralement sous licence libre **GNU AGPLv3**.

---

## 4. Socle de Sécurité et Fonctionnalités Innovantes pour l'Administration

1. **Identité vérifiée, 2FA TOTP et Gestion des Rôles (RBAC)** :
   - Inscriptions publiques fermées (`enable_registration: false`). Seul un Administrateur Sécurité (`ADMIN_SG`) peut enrôler un agent avec son matricule et son ministère.
   - **Authentification forte à 2 facteurs** : Mot de passe Matrix (12 caractères min.) + **Code TOTP à 6 chiffres (RFC 6238)**.
   - **3 Rôles administratifs** : `ADMIN_SG` (DGTD/SG : enrôlement, révocation), `DIRECTEUR` (Instructions de service, messages Confidentiels), `AGENT_PUBLIC` (échanges standards et Diffusion Restreinte).
2. **Révocation immédiate et Bouton d'Urgence (Panic Wipe)** :
   - En un clic ou via `./scripts/revoke.sh`, le compte d'un agent est désactivé (`/_synapse/admin/v1/deactivate`), toutes ses sessions actives sont purgées immédiatement (`HTTP 401`), il est retiré de tous les salons et la clé de session Megolm est renouvelée.
   - **Bouton d'urgence sur le terrain** : permet à un agent en zone à risque d'effacer instantanément les clés cryptographiques locales de son appareil et d'auto-révoquer sa session.
3. **Niveaux de Classification des Messages (`Normal`, `Diffusion Restreinte`, `Confidentiel État`)** :
   - Règles automatiques selon la classification : blocage de la copie et du transfert côté client, bandeau d'alerte anti-capture, et **expiration automatique (TTL)** supprimant les messages expirés côté client et serveur.
4. **Instructions de Service à Valeur Probante (Accusés de lecture signés)** :
   - Un Directeur peut marquer un message comme *Instruction de Service*. Chaque agent destinataire clique sur *« Accuser réception »*, générant un reçu horodaté avec son matricule et une signature cryptographique **HMAC-SHA256** infalsifiable, sans révéler le contenu du message au serveur.
5. **Inclusion Linguistique : Interface et Notes Vocales en Langues Nationales (Bonus)** :
   - Interface traduite dynamiquement en **Français, Mooré, Dioula (Julakan) et Fulfuldé**, accompagnée d'un module de **notes vocales chiffrées de bout en bout** pour faciliter la communication rapide avec les agents de terrain.
6. **Annuaire Officiel par Ministère** :
   - Répertoire structuré par institution (`MTDPCE`, `MEFP`, `MATDS`, `MS`, `SGG-CM`), direction, fonction et statut d'habilitation en temps réel.

---

## 5. Répartition des Rôles au sein de l'Équipe

| Membre de l'équipe | Rôle principal | Responsabilités techniques (Code maîtrisé pour l'entretien) |
|---|---|---|
| **Membre 1** *(Chef de projet & Sécurité)* | Architecture Matrix & Cryptographie | Configuration Synapse (`homeserver.yaml`), chiffrement Olm/Megolm & WebCrypto (`app.js`), script `check_server_blind.sh`, Note de sécurité. |
| **Membre 2** *(Backend & Identité)* | Authentification 2FA, RBAC & Révocation | Implémentation TOTP RFC 6238 (`totp.js`), RBAC (`roles.js`), révocation immédiate (`revoke.sh`, `matrix_engine.js`), tests automatisés (`security.test.js`). |
| **Membre 3** *(Frontend & Innovations)* | Expérience Utilisateur & Métier État | Interface multilingue FR/Mooré/Dioula/Fulfuldé, classification et expiration, accusés de lecture signés (`receipts.js`), vidéo de démonstration. |

