#!/bin/sh

sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true

RNDC_KEY="/etc/bind/rndc.key"

# if [ -f "$RNDC_KEY" ]; then
#     chown 101:101 "$RNDC_KEY" || true
#     chmod 640 "$RNDC_KEY" || true
# fi