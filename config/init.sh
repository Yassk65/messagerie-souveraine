#!/bin/sh
# Initialisation idempotente : secrets, configs, clé de signature.
set -eu

SECRETS=/data/secrets.env
if [ ! -f "$SECRETS" ]; then
  gen() { python -c 'import secrets;print(secrets.token_urlsafe(48))'; }
  {
    echo "REG_SECRET=$(gen)"
    echo "MACAROON_SECRET=$(gen)"
    echo "FORM_SECRET=$(gen)"
  } > "$SECRETS"
fi
. "$SECRETS"

mkdir -p /bootstrap
printf '%s' "$REG_SECRET" > /bootstrap/registration-secret
for name in service-password portal-signing-key portal-storage-key; do
  if [ ! -f "/bootstrap/$name" ]; then
    python -c 'import secrets;print(secrets.token_hex(32))' > "/bootstrap/$name"
  fi
done
chown -R 1000:1000 /bootstrap
chmod 700 /bootstrap
chmod 600 /bootstrap/*

render() {
  sed -e "s|__SERVER_NAME__|${SERVER_NAME}|g" \
      -e "s|__PUBLIC_BASEURL__|${PUBLIC_BASEURL}|g" \
      -e "s|__POSTGRES_PASSWORD__|${POSTGRES_PASSWORD}|g" \
      -e "s|__REG_SECRET__|${REG_SECRET}|g" \
      -e "s|__MACAROON_SECRET__|${MACAROON_SECRET}|g" \
      -e "s|__FORM_SECRET__|${FORM_SECRET}|g" \
      "$1" > "$2"
}

render /templates/homeserver.yaml.tpl /data/homeserver.yaml
if [ "${DEMO_MODE:-false}" = "true" ]; then
  cat >> /data/homeserver.yaml <<'DEMO'

# Explicit demo-only limits for repeatable local acceptance tests.
rc_login:
  address: { per_second: 2, burst_count: 30 }
  account: { per_second: 2, burst_count: 30 }
  failed_attempts: { per_second: 0.5, burst_count: 10 }
DEMO
fi
render /templates/element-config.json.tpl /element/config.json
cp /templates/log.config /data/log.config

python -m synapse.app.homeserver --config-path=/data/homeserver.yaml --generate-keys
chown -R 991:991 /data
echo "[init] OK"
