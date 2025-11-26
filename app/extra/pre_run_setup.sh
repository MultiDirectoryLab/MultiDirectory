#!/bin/sh

chown - R bind:bind /opt/dns_server_file/
chown - R bind:bind /etc/bind/dns_server_config/
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true