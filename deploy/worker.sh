#!/bin/sh
set -u
last_prune=0
while :; do
    python manage.py dispatch_account_recovery
    now=$(date +%s)
    if [ "$((now - last_prune))" -ge 3600 ]; then
        if python manage.py prune_auth_state; then
            last_prune=$now
        fi
    fi
    sleep 60
done
