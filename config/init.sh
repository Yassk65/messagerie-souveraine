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
render /templates/element-config.json.tpl /element/config.json
cp /templates/log.config /data/log.config

python -m synapse.app.homeserver --config-path=/data/homeserver.yaml --generate-keys
chown -R 991:991 /data
echo "[init] OK"
