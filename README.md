# FasoSouverain — Messagerie de l’administration

Interface responsive intégrée à partir des six maquettes Stitch fournies : connexion, messages, annuaire, console de sécurité, actions critiques et discussion mobile.

Le navigateur utilise **matrix-js-sdk et son moteur Rust/WASM** pour Olm/Megolm. Synapse stocke les événements chiffrés et les médias dans PostgreSQL et son volume média. Le portail Node sert les fichiers compilés par Vite, assure le TOTP, les habilitations et une passerelle Matrix authentifiée. Toutes les ressources visuelles sont locales.

## Démarrer en démonstration (PowerShell)

```powershell
$env:DEMO_MODE = 'true'
docker compose up -d --build
```

Ouvrir [FasoSouverain](http://localhost:3000). Dans « Comptes fictifs de démonstration », choisir `admin`, `aminata.ouedraogo`, `ibrahim.sawadogo` ou `fatoumata.kabore`. Mot de passe : `Demo-Fictif-2026!`.

L’environnement local livré utilise `.env` pour isoler la démo vierge dans les volumes `messagerie-souveraine_demo_*` et `data/demo/`. Les données des tests restent dans les volumes précédents et `data/synapse/`. Les variables optionnelles `POSTGRES_VOLUME`, `PORTAL_VOLUME`, `BOOTSTRAP_VOLUME`, `SYNAPSE_DATA_DIR` et `ELEMENT_DATA_DIR` sélectionnent cet ensemble cohérent de données ; ne pas mélanger leurs sauvegardes.

À la première connexion, scanner le QR avec FreeOTP, Aegis ou une application TOTP, puis saisir le code à six chiffres. Il n’existe pas de code TOTP public de contournement. Le QR ne réapparaît pas après validation.

Les comptes sont créés automatiquement et les connexions répétées disposent de limites spécifiques à la démonstration. Aucun contenu de conversation fictif n’est injecté. Démarrer une conversation depuis l’annuaire, ou créer un canal avec le bouton de composition.

## Installation hors démonstration

Copier `.env.example` en `.env`, garder `DEMO_MODE=false`, définir `BOOTSTRAP_ADMIN_PASSWORD` (12 caractères minimum) et remplacer les mots de passe PostgreSQL. Employer des secrets alphanumériques pour les valeurs injectées dans la configuration et les URL PostgreSQL.

```powershell
docker compose up -d --build
```

Un seul agent `admin` est créé à la première initialisation. Il configure son TOTP puis enrôle les autres agents dans la console de sécurité. Le registre persistant ne recharge pas les comptes fictifs quand le mode démo est désactivé. Désactiver le mode démo ne supprime pas les comptes déjà créés : révoquer les comptes fictifs ou utiliser une installation distincte pour une exploitation réelle.

Seul `127.0.0.1:3000` est publié. Synapse, ses API d’administration et les bases ne sont pas exposés sur l’hôte. L’ancien client Element n’est plus utilisé, car son accès direct contournerait les contrôles du portail. Lors d’une mise à niveau de l’ancien Compose, arrêter l’ancien service Element.

Pour une installation distante, placer un reverse-proxy HTTPS devant le portail, adapter le bind du port à l’architecture choisie, définir `COOKIE_SECURE=true` et `PUBLIC_BASEURL=https://votre-domaine/matrix`. Conserver les chemins `/api/` et `/matrix/`, autoriser les requêtes de synchronisation de 40 secondes et les téléversements de 15 Mo. Ne pas exposer Synapse directement. Ne pas changer `SERVER_NAME` après initialisation.

## Utilisation

- **Annuaire** : échanges directs au sein du ministère ; demande et acceptation obligatoires entre administrations.
- **Messages** : synchronisation Matrix, salons chiffrés, fichiers jusqu’à 14 Mo, notes vocales jusqu’à trois minutes. Le microphone nécessite HTTPS ou localhost et l’autorisation du navigateur.
- **Instructions** : réservées aux directeurs et administrateurs ; le destinataire peut enregistrer un accusé HMAC horodaté. Ce reçu est authentifié par le serveur, sans prétendre à une signature personnelle non répudiable.
- **Récupération** : dans les détails cryptographiques, activer la sauvegarde, confirmer le mot de passe si demandé, puis conserver la clé affichée hors de l’appareil. Sur un nouveau navigateur, utiliser « Restaurer les clés ». Les appareils peuvent aussi être vérifiés par comparaison de codes dans « Sécurité ».
- **Sécurité** : enrôlement, révocation et journal global réservés à `ADMIN_SG`. Chaque agent peut consulter ses propres appareils.
- **Urgence** : confirmation explicite avant désactivation du compte et suppression des clés locales. Une purge hors connexion ne confirme pas la révocation serveur. Les sauvegardes chiffrées et les copies déjà déchiffrées ailleurs ne sont pas effacées.

L’expiration masque les messages dans ce client ; elle ne constitue pas une suppression irréversible de toutes les copies serveur ou destinataires. La sélection de texte est limitée dans l’interface pour les messages classifiés, sans pouvoir empêcher les captures d’écran. Les noms des salons, participants, classifications, échéances et horodatages restent des métadonnées de routage visibles.

## Développement et vérification

Node.js 22 est utilisé dans Docker. En local :

```powershell
cd portal
npm ci
npm run build
npm test
```

Pour modifier l’interface avec rechargement automatique : `npm run dev`. Les chemins API sont relayés vers le portail Docker sur le port 3000. Un navigateur ne peut ouvrir simultanément le même stockage cryptographique d’appareil dans plusieurs onglets.

Tests navigateur complets contre une installation locale de démonstration (Microsoft Edge installé) :

```powershell
node tests/e2e.cjs
```

Pour inclure récupération, comparaison SAS, enrôlement, révocation, purge et redémarrage des services :

```powershell
$env:FASO_EXTENDED = 'true'
$env:FASO_TEST_RESTART = 'true'
node tests/e2e.cjs
Get-Content -Raw tests/synapse-live.cjs | docker compose exec -T portal node
```

Les captures et les secrets des comptes fictifs nécessaires aux répétitions sont conservés dans `data/e2e/`, exclu de Git. Ne pas utiliser ce script contre des comptes réels. Les tests unitaires injectent explicitement le moteur en mémoire ; aucun simulateur n’est utilisé au démarrage normal. Synapse indisponible produit une erreur visible.

Les tests navigateur valident et scellent le TOTP des comptes utilisés. Ils doivent être exécutés sur un environnement de test : pour les répéter, le script réutilise les secrets fictifs du fichier associé à l’instance dans `data/e2e/`. La démo livrée après validation reste disponible pour un premier enrôlement par son utilisateur.

Le script `scripts/check_server_blind.sh` inspecte les types d’événements réellement stockés. Pour révoquer en CLI après configuration du TOTP administrateur :

```sh
ADMIN_PASSWORD='votre-mot-de-passe' ADMIN_TOTP=123456 ./scripts/revoke.sh identifiant
```

## Persistance, sauvegardes et mise à niveau

La base dédiée `portal-db` contient un registre versionné chiffré AES-256-GCM : agents, secrets TOTP, demandes, accusés, audit, correspondances des salons et sessions serveur. Un verrou PostgreSQL impose une seule instance du portail. Les mutations sont sérialisées et enregistrées avant l’envoi d’une réponse de succès. Les intentions d’enrôlement et de révocation sont enregistrées pour reprise au démarrage.

Sauvegarder ensemble, avec les services arrêtés ou une méthode de snapshot cohérente :

- PostgreSQL Synapse (`pgdata`) et PostgreSQL portail (`portaldata`), idéalement par `pg_dump` ;
- `data/synapse/`, notamment les médias et la clé de signature Synapse ;
- le volume `bootstrap`, qui contient les secrets de chiffrement du registre et le compte de service.

Restaurer les bases et les volumes correspondants avant de redémarrer. La perte de `portal-storage-key` rend le registre illisible. La clé de récupération des agents reste distincte de ces secrets. Aucune migration de l’historique du simulateur n’est effectuée. La migration SQL `001_registry.sql` initialise la version 1 du registre de manière idempotente.

Licence AGPL-3.0-only. Matrix JS SDK, moteur Rust, bibliothèque de chiffrement des pièces jointes et polices conservent leurs licences distribuées avec leurs paquets.
