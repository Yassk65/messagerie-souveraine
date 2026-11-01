server_name: "__SERVER_NAME__"
public_baseurl: "__PUBLIC_BASEURL__/"
pid_file: /data/homeserver.pid
report_stats: false
signing_key_path: "/data/signing.key"
log_config: "/data/log.config"
media_store_path: /data/media_store

listeners:
  - port: 8008
    tls: false
    type: http
    x_forwarded: true
    bind_addresses: ['0.0.0.0']
    resources:
      - names: [client]      # PAS de ressource "federation" : serveur fermé
        compress: false

database:
  name: psycopg2
  args:
    user: synapse
    password: "__POSTGRES_PASSWORD__"
    database: synapse
    host: db
    cp_min: 5
    cp_max: 10

# --- Identité : seuls des agents enrôlés par un administrateur ---
enable_registration: false
registration_shared_secret: "__REG_SECRET__"
macaroon_secret_key: "__MACAROON_SECRET__"
form_secret: "__FORM_SECRET__"
allow_guest_access: false
password_config:
  enabled: true
  policy:
    enabled: true
    minimum_length: 12

# --- Chiffrement de bout en bout forcé (Olm/Megolm) pour tous les types de salons ---
encryption_enabled_by_default_for_room_type: all

# --- Souveraineté : aucun appel vers un service tiers, pas de fédération ---
federation_domain_whitelist: []
trusted_key_servers: []
suppress_key_server_warning: true
url_preview_enabled: false
allow_public_rooms_without_auth: false
allow_public_rooms_over_federation: false
enable_room_list_search: false

# --- Minimisation des métadonnées ---
presence:
  enabled: false
user_ips_max_age: 1d
redaction_retention_period: 1d
push:
  include_content: false
