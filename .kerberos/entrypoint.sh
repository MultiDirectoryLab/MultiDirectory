#!/bin/bash

set -e

sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true
cd /server

uvicorn --factory config_server:create_app \
  --host 0.0.0.0 \
  --ssl-keyfile=/certs/krbkey.pem \
  --ssl-certfile=/certs/krbcert.pem \
  --reload
