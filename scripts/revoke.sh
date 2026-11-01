#!/bin/sh
# Usage : ADMIN_PASSWORD=... ADMIN_TOTP=123456 ./scripts/revoke.sh agent
set -eu
TARGET="${1:?Usage: revoke.sh <identifiant>}"
: "${ADMIN_PASSWORD:?ADMIN_PASSWORD requis}"
: "${ADMIN_TOTP:?ADMIN_TOTP requis}"
export ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
docker compose exec -T -e ADMIN_USERNAME -e ADMIN_PASSWORD -e ADMIN_TOTP portal node src/admin-cli.js "$TARGET"
