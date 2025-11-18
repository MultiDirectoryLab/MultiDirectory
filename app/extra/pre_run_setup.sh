#!/bin/sh

chown -R bind:bind /DNS_server_file /DNS_server_configs || true
chown bind:bind /resolv.conf || true

sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true