#!/bin/sh

ARG UNAME=bind
ARG UID=100
ARG GID=101
RUN groupadd -g $GID -o $UNAME
RUN useradd -m -u $UID -g $GID -o -s /bin/bash $UNAME
USER $UNAME
CMD /bin/bash

chown $UID:$GID /etc/bind/rndc.key
# chown - R $UID:$GID /opt/dns_server_file/
# chown - R $UID:$GID /etc/bind/dns_server_config/
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.d/stash.keyfile || true
sed -i 's/ou=users/cn=users/g' /etc/kdc/krb5.conf || true