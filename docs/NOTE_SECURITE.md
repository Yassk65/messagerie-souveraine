# Note de Sécurité — « FasoSouverain » : Messagerie Souveraine de l'Administration
**Hackathon 226 – Édition 2026 (MTDPCE / DGTD) · Sprint Technique Pré-Hackathon**

---

## 1. Modèle de Menaces Pris en Compte (Contexte Administratif Burkinabè)

Dans le cadre des communications de l'administration publique, nous considérons cinq menaces principales :

1. **M1 — Espionnage par des opérateurs ou services étrangers (Perte de souveraineté)** :
   - *Scénario* : Utilisation de serveurs cloud tiers ou de services de notifications externes (Google FCM / Apple APNs) permettant l'interception du graphe social ou des contenus.
2. **M2 — Compromission ou curiosité de l'administrateur système / base de données (« Serveur honnête mais curieux »)** :
   - *Scénario* : Un attaquant ou un administrateur ayant un accès direct à la base PostgreSQL ou aux captures réseau tente de lire les échanges ministériels ou les fichiers joints.
3. **M3 — Perte, vol d'appareil sur le terrain ou départ d'un agent public** :
   - *Scénario* : Un agent en mission perd son téléphone déverrouillé, ou quitte ses fonctions tout en conservant ses jetons d'accès actifs pour écouter les groupes de travail.
4. **M4 — Intrusion d'un tiers non habilité ou usurpation de compte (Mot de passe compromis)** :
   - *Scénario* : Un individu externe tente de s'inscrire sur le serveur, de joindre un salon par fédération, ou de se connecter avec un mot de passe divulgué.
5. **M5 — Fuite interne d'informations sensibles ou déni de réception d'une instruction officielle** :
   - *Scénario* : Un agent transfère par erreur un message sensible hors de son service, ou conteste avoir reçu une instruction urgente de sa hiérarchie.

---

## 2. Protections Mises en Place

### 2.1. Chiffrement de Bout en Bout (E2EE) — « Le serveur ne lit rien » (Contre M2)
- **Protocole éprouvé sans cryptographie maison** : Utilisation du standard ouvert **Matrix (Olm / Megolm)** associé à l'API standard **WebCrypto (`AES-256-GCM`, dérivation `PBKDF2-SHA256`)**.
- **Forçage intégral** : Le serveur Synapse impose `encryption_enabled_by_default_for_room_type: all`. Le portail souverain bloque et rejette avec une erreur `HTTP 400` tout évènement non chiffré de type `m.room.message`.
- **Preuve vérifiable en base** : Seuls des évènements `m.room.encrypted` contenant le texte chiffré (`ciphertext`) et le vecteur d'initialisation (`iv`) sont stockés dans PostgreSQL. Le script `./scripts/check_server_blind.sh` et l'endpoint `/api/security/blind-check` vérifient à tout instant que `SELECT count(*) FROM events WHERE type = 'm.room.message'` retourne **`0`**.

### 2.2. Hébergement 100 % Souverain et Isolation Réseau (Contre M1 & M4)
- **Zéro dépendance externe** : Aucune API tierce n'est appelée. Les serveurs de clés tiers sont désactivés (`trusted_key_servers: []`), les aperçus de liens web sont coupés (`url_preview_enabled: false`) pour éviter toute fuite d'URL vers l'extérieur, et la télémétrie est désactivée (`report_stats: false`).
- **Fédération totalement fermée** : Le listener Synapse n'expose que la ressource `[client]` (pas de ressource `federation`) et `federation_domain_whitelist: []` interdit toute communication avec un serveur Matrix extérieur.

### 2.3. Identité Vérifiée, Authentification Forte (2FA TOTP) et RBAC (Contre M4 & M5)
- **Enrôlement fermé** : `enable_registration: false` et `allow_guest_access: false`. Tout compte non pré-enrôlé par l'administrateur est rejeté immédiatement (`HTTP 403 INTRUS_REJETE`).
- **Second facteur TOTP (RFC 6238)** : Après validation du mot de passe (12 caractères min.), l'agent doit fournir un code temporel à 6 chiffres calculé par `HMAC-SHA1` sur fenêtre de 30 secondes (`portal/src/totp.js`), comparé en temps constant (`crypto.timingSafeEqual`) pour contrer les attaques temporelles (*Timing Attacks*).
- **Contrôle d'accès basé sur les rôles (RBAC)** : Séparation stricte entre `ADMIN_SG` (enrôlement/révocation), `DIRECTEUR` (émission de messages `CONFIDENTIEL` et d'instructions de service) et `AGENT_PUBLIC`.

### 2.4. Révocation Immédiate et Bouton d'Urgence (Contre M3)
- **Révocation serveur instantanée** : Lorsqu'un administrateur révoque un agent (via l'interface Admin ou `./scripts/revoke.sh`), l'API `/_synapse/admin/v1/deactivate` et le moteur de session invalident immédiatement tous ses `access_token` sur tous ses appareils, le retirent de tous les salons chiffrés (`membership: leave`) et déclenchent le renouvellement de la clé Megolm pour que les futurs messages lui soient cryptographiquement inaccessibles.
- **Bouton d'urgence (Panic Wipe)** : Permet à un agent menacé d'effacer en un clic le stockage local de son navigateur (`CryptoKey`, `localStorage`, `sessionStorage`) et de révoquer ses jetons côté serveur.

### 2.5. Classification, Expiration et Accusés Signés (Contre M5)
- **Expiration automatique (TTL)** : Les messages classés `DIFFUSION_RESTREINTE` ou `CONFIDENTIEL` portent une échéance au-delà de laquelle ils sont purgés automatiquement.
- **Accusé de lecture à valeur probante** : Lorsqu'un agent accuse réception d'une Instruction de Service, le système calcule une signature **HMAC-SHA256** (`portal/src/receipts.js`) sur l'identifiant d'évènement, le matricule, le ministère et l'horodatage UTC, garantissant la non-répudiation administrative sans stocker le texte du message.

---

## 3. Minimisation des Métadonnées : Ce que le Serveur Voit vs Ne Voit Pas

Conformément aux exigences de transparence du sprint, voici la matrice exacte de visibilité côté serveur :

| Donnée / Information | Visible par le serveur ? | Justification et Mesure de réduction appliquée |
|---|---|---|
| **Contenu des messages et notes vocales** | ❌ **NON (Chiffré)** | Chiffré de bout en bout (Megolm / AES-256-GCM) avant envoi (`m.room.encrypted`). |
| **Contenu des fichiers partagés** | ❌ **NON (Chiffré)** | Chiffré côté client avant téléversement ; le serveur ne stocke qu'un blob binaire opaque. |
| **Statut « En ligne / Hors ligne / Frappe »** | ❌ **NON (Désactivé)** | Désactivé dans `homeserver.yaml` (`presence: enabled: false`) pour éviter le profilage d'activité. |
| **Aperçu des liens partagés (URL Preview)** | ❌ **NON (Désactivé)** | Désactivé (`url_preview_enabled: false`) pour que le serveur n'interroge jamais les liens cités. |
| **Contenu dans les notifications Push** | ❌ **NON (Désactivé)** | `push: include_content: false` (seul un signal de réveil sans texte ni expéditeur est émis). |
| **Adresses IP de connexion des agents** | ⚠️ **Limité (24h max)** | Purge automatique forcée à 1 jour dans Synapse (`user_ips_max_age: 1d`). |
| **Messages supprimés / expirés** | ⚠️ **Limité (Purge)** | Rétention réduite au minimum (`redaction_retention_period: 1d`) + purge active des TTL expirés. |
| **Qui est membre de quel salon et quand un évènement chiffré transite** | ✅ **OUI (Inhérent au routage)** | Nécessaire à Synapse pour acheminer les paquets chiffrés aux bons destinataires et gérer les droits des salons. Réduit par l'utilisation d'identifiants de salons opaques (`!id:domaine`). |

---

## 4. Limites Connues et Recommandations de Déploiement en Production

1. **Métadonnées de routage résiduelles** : Bien que le serveur soit totalement aveugle au contenu, il connaît la liste des membres d'un salon, l'horodatage d'envoi et la taille approximative des paquets chiffrés.
2. **Protection contre les captures d'écran physiques** : L'application bloque le copier-coller sur les messages classifiés et affiche un bandeau dissuasif, mais sur un navigateur web standard (et face à une photo prise avec un second téléphone), le blocage matériel complet nécessite une application mobile native compilée avec `FLAG_SECURE` (Android) et gérée par MDM gouvernemental.
3. **Messages déjà déchiffrés avant révocation** : Si un appareil est volé hors-ligne (mode avion), la révocation empêche tout nouveau message d'arriver mais l'effacement local ne s'exécute qu'à la reconnexion réseau de l'appareil (d'où l'expiration courte `TTL` sur les messages `CONFIDENTIEL`).
4. **Durcissement TLS en production** : Pour la démonstration locale du hackathon, les ports sont accessibles en HTTP (`localhost:3000`, `localhost:8080`, `localhost:8008`). En production ministérielle, un reverse-proxy souverain (Nginx / Caddy) avec certificats TLS 1.3 doit être placé en frontal et restreindre la route `/_synapse/admin` au seul réseau d'administration de la DGTD.

