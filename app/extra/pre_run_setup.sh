#!/bin/sh

chown -R md:md /app \
            /app/logs \
            /venvs \
            /LDAP_keytab \
            /certs \
            /DNS_server_file \
            /DNS_server_configs  \
            /audit  || true
chown md:md /resolv.conf || true

sed -i 's/ou=users/cn=users/g' /etc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/krb5.conf || true