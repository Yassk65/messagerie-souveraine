#!/bin/sh
# Crée les comptes fictifs via le provisioning idempotent du portail.
set -eu
DEMO_MODE=true docker compose up -d --build
printf '%s\n' 'Mode démonstration activé : http://localhost:3000. Configurez le TOTP à la première connexion.'
