#!/bin/sh
# Révocation immédiate d'un agent (départ, perte du téléphone).
# Désactive le compte : tous les appareils sont déconnectés, jetons supprimés,
# l'agent quitte tous les salons (les clés de groupe sont alors renouvelées).
# Usage : ADMIN_PASSWORD=... ./scripts/revoke.sh aminata.ouedraogo
set -eu
USER_LOCALPART="${1:?Usage: revoke.sh <identifiant>}"
SERVER_NAME="${SERVER_NAME:-localhost}"
BASE="${PUBLIC_BASEURL:-http://localhost:8008}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-Demo-Fictif-2026!}"

TOKEN=$(curl -fsS -X POST "$BASE/_matrix/client/v3/login" \
  -H 'Content-Type: application/json' \
  -d "{\"type\":\"m.login.password\",\"identifier\":{\"type\":\"m.id.user\",\"user\":\"admin\"},\"password\":\"$ADMIN_PASSWORD\"}" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
[ -n "$TOKEN" ] || { echo "Connexion admin impossible" >&2; exit 1; }

curl -fsS -X POST "$BASE/_synapse/admin/v1/deactivate/@${USER_LOCALPART}:${SERVER_NAME}" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"erase": false}'
echo
echo "Agent @${USER_LOCALPART}:${SERVER_NAME} révoqué."
