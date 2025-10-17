#!/bin/sh

chown -R md:md /app \
            /app/logs \
            /venvs \
            /LDAP_keytab \
            /certs \
            /DNS_server_file \
            /DNS_server_configs  \
            /resolv.conf  \
            /audit  || true
