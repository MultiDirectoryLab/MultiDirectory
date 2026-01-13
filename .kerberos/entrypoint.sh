#!/bin/bash

set -e

sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true

fix_configs() {
    for file in /etc/krb5.conf /etc/kdc.conf /etc/krb5.d/stash.keyfile; do
        if [ -f "$file" ]; then
            sed -i 's/ou=services/ou=System/g' "$file" 2>/dev/null || true
            sed -i 's/ou=users/cn=users/g' "$file" 2>/dev/null || true
        fi
    done
}

fix_configs

(
    for i in {1..10}; do
        sleep 3
        fix_configs
    done
) &


cd /server




uvicorn --factory config_server:create_app \
  --host 0.0.0.0 \
  --ssl-keyfile=/certs/krbkey.pem \
  --ssl-certfile=/certs/krbcert.pem \
  --reload
