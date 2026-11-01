#!/bin/sh
# Crée des comptes FICTIFS de démonstration (aucune donnée réelle).
# Usage : ./scripts/demo_accounts.sh
set -eu
PASS="${DEMO_PASSWORD:-Demo-Fictif-2026!}"

create() {  # $1=utilisateur  $2=-a (admin) ou --no-admin
  docker compose exec -T synapse register_new_matrix_user \
    -c /data/homeserver.yaml -u "$1" -p "$PASS" "$2" http://localhost:8008 \
    || echo "(compte $1 déjà existant ?)"
}

create admin --admin
create aminata.ouedraogo --no-admin
create ibrahim.sawadogo  --no-admin
create fatoumata.kabore  --no-admin
echo "Comptes fictifs créés. Mot de passe de démonstration : $PASS"
