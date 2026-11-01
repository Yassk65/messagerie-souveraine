#!/bin/sh
# Épreuve « le serveur ne lit rien » : aucun message en clair dans la base.
# Retourne un code d'erreur si un m.room.message est trouvé.
set -eu
psql_q() { docker compose exec -T db psql -U synapse -d synapse -t -A -c "$1"; }

echo "== Types d'évènements stockés par le serveur =="
psql_q "SELECT type, count(*) FROM events GROUP BY type ORDER BY 2 DESC;"

CLEAR=$(psql_q "SELECT count(*) FROM events WHERE type = 'm.room.message';" | tr -d '[:space:]')
echo "== Messages en clair : $CLEAR =="
if [ "$CLEAR" != "0" ]; then
  echo "ECHEC : des messages en clair existent côté serveur (salon non chiffré ?)" >&2
  exit 1
fi
echo "OK : seuls des m.room.encrypted sont présents."
