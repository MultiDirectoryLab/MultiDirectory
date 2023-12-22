#!/bin/bash
echo -e "base ${BASE}\nuri ${SERVER}\nbinddn ${BIND_DN}\nbindpw ${BASE_PASSWORD}" > /etc/nslcd.conf

for item in passwd shadow group; do
    sed -i "s/^${item}:.*/${item}: files ldap/g" /etc/nsswitch.conf
done

/usr/sbin/nslcd
/usr/sbin/rsyslogd
/usr/sbin/sshd

tail -F /var/log/auth.log
