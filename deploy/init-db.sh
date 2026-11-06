#!/bin/sh
set -eu

SAFEVAULT_APP_PASSWORD=$(cat /run/secrets/database-password)
if [ -z "$SAFEVAULT_APP_PASSWORD" ]; then
    echo "The SafeVault database password file is empty." >&2
    exit 1
fi
export SAFEVAULT_APP_PASSWORD
psql --no-psqlrc -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<'SQL'
\getenv app_password SAFEVAULT_APP_PASSWORD
CREATE ROLE safevault LOGIN PASSWORD :'app_password';
CREATE DATABASE safevault OWNER safevault;
REVOKE CONNECT ON DATABASE safevault FROM PUBLIC;
SQL
unset SAFEVAULT_APP_PASSWORD
